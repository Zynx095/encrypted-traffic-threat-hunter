"""
Bounded TCP Stream Reassembly for TLS Handshake Acquisition.

Provides memory-bounded, sequence-aware TCP stream defragmentation for live
capture adapters. Correctly handles:
- Multi-segment ClientHello/ServerHello fragmentation across MTU/MSS boundaries
- Out-of-order segment arrival
- Overlapping segments and TCP retransmissions
- Bounded memory limits (max 16 KB per stream) to prevent buffer exhaustion
- Early rejection of non-TLS payloads (zero unnecessary memory retention)
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_MAX_REASSEMBLY_BUFFER = 16384  # 16 KB (RFC 8446 max TLS plaintext record size)
TLS_HANDSHAKE_TYPE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_SERVER_HELLO = 0x02


def seq_diff(s1: int, s2: int) -> int:
    """Computes (s1 - s2) with 32-bit unsigned TCP sequence number wraparound."""
    diff = (s1 - s2) & 0xFFFFFFFF
    if diff >= 0x80000000:
        diff -= 0x100000000
    return diff


class TcpStreamReassembler:
    """
    Directional TCP Stream Reassembler.
    Buffers and reassembles incoming TCP segments for a single direction
    until a complete TLS Handshake record is formed or memory limit is reached.
    """

    def __init__(self, max_buffer_size: int = DEFAULT_MAX_REASSEMBLY_BUFFER):
        self.max_buffer_size = max_buffer_size
        self.expected_seq: Optional[int] = None
        self.assembled = bytearray()
        self.out_of_order: Dict[int, bytes] = {}  # seq -> payload
        self.is_tls: Optional[bool] = None
        self.target_record_length: Optional[int] = None
        self.completed = False

    def reset(self) -> None:
        """Clear all buffers and reset state."""
        self.expected_seq = None
        self.assembled.clear()
        self.out_of_order.clear()
        self.is_tls = None
        self.target_record_length = None
        self.completed = False

    def add_segment(self, seq: int, payload: bytes) -> Optional[bytes]:
        """
        Ingests a TCP segment with its sequence number and payload.
        Returns the complete reassembled TLS record bytes if complete, or None if still accumulating.
        """
        if self.completed or not payload:
            return bytes(self.assembled) if self.completed else None

        # If stream is not yet anchored to a sequence number:
        if self.expected_seq is None:
            if payload[0] == TLS_HANDSHAKE_TYPE:
                # This segment is the start of the TLS Handshake record
                self.expected_seq = seq
                self.is_tls = True
            else:
                # Fast reject clear non-TLS protocol signatures
                if payload.startswith((b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"CONNECT", b"SSH-", b"220 ")):
                    self.is_tls = False
                    self.completed = True
                    self.out_of_order.clear()
                    return None
                # Buffer potential out-of-order fragment
                if len(payload) <= self.max_buffer_size:
                    self.out_of_order[seq] = payload
                if sum(len(p) for p in self.out_of_order.values()) > 4096:
                    self.is_tls = False
                    self.completed = True
                    self.out_of_order.clear()
                return None

        # Calculate offset from expected sequence number
        offset = seq_diff(seq, self.expected_seq)

        if offset < 0:
            # Segment starts before expected_seq (retransmission or overlap)
            overlap = -offset
            if overlap >= len(payload):
                # Entire segment is a duplicate
                return self._check_completion()
            # Trim the already-received prefix
            payload = payload[overlap:]
            seq = (seq + overlap) & 0xFFFFFFFF
            offset = 0

        if offset == 0:
            # Contiguous with current stream
            to_append = payload
            if len(self.assembled) + len(to_append) > self.max_buffer_size:
                to_append = to_append[:self.max_buffer_size - len(self.assembled)]

            self.assembled.extend(to_append)
            self.expected_seq = (self.expected_seq + len(to_append)) & 0xFFFFFFFF

            # Check if this payload starts with TLS Handshake (0x16)
            if self.is_tls is None and len(self.assembled) > 0:
                if self.assembled[0] != TLS_HANDSHAKE_TYPE:
                    self.is_tls = False
                    self.completed = True
                    return None
                self.is_tls = True

            # Drain any contiguous out-of-order segments
            self._drain_contiguous()

        else:
            # Out-of-order segment arriving ahead of expected_seq
            if len(self.assembled) + offset + len(payload) <= self.max_buffer_size * 2:
                self.out_of_order[seq] = payload

        return self._check_completion()

    def _drain_contiguous(self) -> None:
        """Check and attach any buffered out-of-order segments contiguous with expected_seq."""
        while self.out_of_order and self.expected_seq is not None:
            candidates = [
                s for s in self.out_of_order
                if seq_diff(s, self.expected_seq) <= 0 and seq_diff((s + len(self.out_of_order[s])) & 0xFFFFFFFF, self.expected_seq) > 0
            ]
            if not candidates:
                break

            best_seq = max(candidates, key=lambda s: seq_diff(s, self.expected_seq))
            seg_payload = self.out_of_order.pop(best_seq)

            d = seq_diff(best_seq, self.expected_seq)
            if d < 0:
                overlap = -d
                if overlap >= len(seg_payload):
                    continue
                seg_payload = seg_payload[overlap:]

            to_append = seg_payload
            if len(self.assembled) + len(to_append) > self.max_buffer_size:
                to_append = to_append[:self.max_buffer_size - len(self.assembled)]

            self.assembled.extend(to_append)
            self.expected_seq = (self.expected_seq + len(to_append)) & 0xFFFFFFFF

            if len(self.assembled) >= self.max_buffer_size:
                break

    def _check_completion(self) -> Optional[bytes]:
        """Verify whether a complete TLS record has been assembled."""
        if not self.assembled or self.assembled[0] != TLS_HANDSHAKE_TYPE:
            return None

        if len(self.assembled) >= 5:
            record_len = int.from_bytes(self.assembled[3:5], "big")
            total_needed = 5 + record_len

            if len(self.assembled) >= total_needed:
                self.completed = True
                result = bytes(self.assembled[:total_needed])
                # Release payload memory immediately after extraction
                self.out_of_order.clear()
                return result

        if len(self.assembled) >= self.max_buffer_size:
            # Reached max buffer limit without complete record; return available window
            self.completed = True
            self.out_of_order.clear()
            return bytes(self.assembled)

        return None
