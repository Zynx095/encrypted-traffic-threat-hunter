"""Bounded reassembly of one TLS Hello message from one direction of a TCP connection.

Used by the offline flow reconstructor and by live capture so that a ClientHello (or ServerHello)
spread over several TCP segments is fingerprinted from its complete bytes, and never from a
partial message.

Policy
------
* Anchor. If the SYN was seen, ``set_isn`` fixes stream offset 0 at ISN+1, so a lost first
  segment is detected. Otherwise offset 0 is the first segment whose payload starts with a
  plausible TLS handshake record header; data before that is ignored.
* Segments are stored by stream offset. Exact or partial retransmissions that carry the same
  bytes are absorbed. Overlaps that carry *different* bytes end the stream as
  ``CONFLICTING_OVERLAP``; no "first wins" or "last wins" guess is made.
* Only the contiguous prefix from offset 0 is parsed. Bytes are never invented: a gap stays a gap
  until it is filled, the connection ends, or the caller times the stream out.
* The handshake message may span several TLS records; every record must be a handshake record
  with a sane length, and the first handshake message must be the expected Hello type.
* Memory is bounded per stream (``max_bytes`` of stream data, ``max_segments`` stored segments).
  A Hello that declares more than ``max_message`` bytes is ``UNSUPPORTED`` rather than buffered.
* Once a stream reaches a terminal outcome it ignores further segments, so a retransmitted or
  repeated Hello on the same connection is reported once.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import Dict, Hashable, List, Optional, Tuple

PENDING = "PENDING"
COMPLETE = "COMPLETE"
INCOMPLETE_TIMEOUT = "INCOMPLETE_TIMEOUT"
INCOMPLETE_EVICTED = "INCOMPLETE_EVICTED"
INCOMPLETE_TERMINATED = "INCOMPLETE_TERMINATED"
MALFORMED = "MALFORMED"
CONFLICTING_OVERLAP = "CONFLICTING_OVERLAP"
UNSUPPORTED = "UNSUPPORTED"
NO_CLIENTHELLO = "NO_CLIENTHELLO"   # stream does not start with the expected Hello (name kept for both directions)
TERMINAL = {COMPLETE, INCOMPLETE_TIMEOUT, INCOMPLETE_EVICTED, INCOMPLETE_TERMINATED, MALFORMED,
            CONFLICTING_OVERLAP, UNSUPPORTED, NO_CLIENTHELLO}

TLS_HANDSHAKE = 0x16
MAX_TLS_RECORD = 16384 + 2048        # RFC 8446 5.2 upper bound for a record fragment
DEFAULT_MAX_MESSAGE = 16384          # largest Hello we reassemble
DEFAULT_MAX_SEGMENTS = 64


_PLAINTEXT_PREFIXES = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT ", b"HTTP/",
                       b"SSH-", b"220 ", b"EHLO", b"HELO")


def seq_diff(s1: int, s2: int) -> int:
    """(s1 - s2) under 32-bit TCP sequence wraparound."""
    diff = (s1 - s2) & 0xFFFFFFFF
    return diff - 0x100000000 if diff >= 0x80000000 else diff


def _plausible_record_header(data: bytes) -> bool:
    return len(data) >= 5 and data[0] == TLS_HANDSHAKE and data[1] == 3 and data[2] <= 4


class HelloReassembler:
    """Reassembles the first TLS handshake message of one TCP direction."""

    def __init__(self, handshake_type: Optional[int] = 0x01, max_message: int = DEFAULT_MAX_MESSAGE,
                 max_segments: int = DEFAULT_MAX_SEGMENTS):
        self.handshake_type = handshake_type
        self._accepted = (0x01, 0x02) if handshake_type is None else (handshake_type,)
        self.max_message = max_message
        self.max_bytes = 2 * max_message + 64        # message plus room for record headers
        self.max_segments = max_segments
        self.anchor: Optional[int] = None
        self.anchored_by_syn = False
        self.segments: Dict[int, bytes] = {}       # stream offset -> bytes
        self.unanchored: Dict[int, bytes] = {}     # seq -> bytes, seen before an anchor existed
        self.outcome = PENDING
        self.detail = ""
        self.segments_seen = 0
        self.result: Optional[bytes] = None

    # ------------------------------------------------------------------ public API --
    @property
    def done(self) -> bool:
        return self.outcome in TERMINAL

    @property
    def buffered_bytes(self) -> int:
        return sum(map(len, self.segments.values())) + sum(map(len, self.unanchored.values()))

    def set_isn(self, isn: int) -> None:
        """Anchor at ISN+1 (call on the SYN of this direction)."""
        if self.anchor is None and not self.done:
            self.anchor = (isn + 1) & 0xFFFFFFFF
            self.anchored_by_syn = True
            self._adopt_unanchored()

    def add_segment(self, seq: int, payload: bytes) -> Optional[bytes]:
        """Add one segment. Returns the Hello as a single TLS record the first time it completes."""
        if self.done or not payload:
            return None
        self.segments_seen += 1
        if self.anchor is None:
            if _plausible_record_header(payload):
                self.anchor = seq
                self._adopt_unanchored()
            elif not self.unanchored and payload.startswith(_PLAINTEXT_PREFIXES):
                self._end(NO_CLIENTHELLO, "stream starts with a plaintext protocol")
                return None
            else:
                self._stash_unanchored(seq, payload)
                return None
        if not self._insert(seq_diff(seq, self.anchor), payload):
            return None
        return self._evaluate()

    def finish(self, outcome: str, detail: str = "") -> str:
        """Close a pending stream (timeout, eviction, FIN/RST). Terminal outcomes are kept."""
        if not self.done:
            self._end(outcome, detail)
        return self.outcome

    # ------------------------------------------------------------------ internals --
    def _end(self, outcome: str, detail: str = "") -> None:
        self.outcome, self.detail = outcome, detail
        self.segments.clear()
        self.unanchored.clear()

    def _stash_unanchored(self, seq: int, payload: bytes) -> None:
        if len(self.unanchored) >= self.max_segments or self.buffered_bytes + len(payload) > self.max_bytes:
            self._end(NO_CLIENTHELLO, "no TLS record header found within the buffering limit")
            return
        self.unanchored.setdefault(seq, payload)

    def _adopt_unanchored(self) -> None:
        pending, self.unanchored = self.unanchored, {}
        for seq, payload in pending.items():
            if self.done:
                return
            self._insert(seq_diff(seq, self.anchor), payload)

    def _insert(self, offset: int, payload: bytes) -> bool:
        if offset < 0:                               # starts before the anchor: keep only the tail
            if -offset >= len(payload):
                return True
            payload, offset = payload[-offset:], 0
        if offset + len(payload) > self.max_bytes:
            payload = payload[:max(0, self.max_bytes - offset)]
            if not payload:
                return True                          # wholly beyond the window: ignore, no buffering
        end = offset + len(payload)
        for o, data in self.segments.items():        # verify every overlap carries identical bytes
            lo, hi = max(o, offset), min(o + len(data), end)
            if lo < hi and data[lo - o:hi - o] != payload[lo - offset:hi - offset]:
                self._end(CONFLICTING_OVERLAP, f"bytes differ at stream offsets {lo}-{hi}")
                return False
        if offset in self.segments and len(self.segments[offset]) >= len(payload):
            return True
        if len(self.segments) >= self.max_segments:
            self._end(UNSUPPORTED, f"more than {self.max_segments} segments buffered")
            return False
        self.segments[offset] = payload
        return True

    def _contiguous(self) -> bytes:
        out = bytearray()
        for o in sorted(self.segments):
            if o > len(out):
                break
            data = self.segments[o]
            if o + len(data) > len(out):
                out += data[len(out) - o:]
        return bytes(out)

    def _evaluate(self) -> Optional[bytes]:
        stream = self._contiguous()
        if not stream:
            return None
        if stream[0] != TLS_HANDSHAKE:
            self._end(NO_CLIENTHELLO, "stream does not start with a TLS handshake record")
            return None
        body = bytearray()
        pos = 0
        while pos + 5 <= len(stream):
            hdr = stream[pos:pos + 5]
            rlen = int.from_bytes(hdr[3:5], "big")
            if hdr[0] != TLS_HANDSHAKE or hdr[1] != 3 or rlen == 0 or rlen > MAX_TLS_RECORD:
                self._end(MALFORMED, f"invalid TLS record header at stream offset {pos}")
                return None
            chunk = stream[pos + 5:pos + 5 + rlen]
            if not body and chunk and chunk[0] not in self._accepted:
                self._end(NO_CLIENTHELLO, f"first handshake message has type {chunk[0]}")
                return None
            body += chunk
            if len(body) >= 4:
                hlen = int.from_bytes(body[1:4], "big")
                if hlen > self.max_message:
                    self._end(UNSUPPORTED, f"Hello declares {hlen} bytes (limit {self.max_message})")
                    return None
                if hlen < 38:
                    self._end(MALFORMED, f"Hello length {hlen} is shorter than its fixed fields")
                    return None
                if len(body) >= 4 + hlen:
                    msg = bytes(body[:4 + hlen])
                    self.result = bytes([TLS_HANDSHAKE]) + stream[1:3] + len(msg).to_bytes(2, "big") + msg
                    self._end(COMPLETE)
                    return self.result
            if len(chunk) < rlen:
                return None                            # wait for the rest of this record
            pos += 5 + rlen
        return None


class ReassemblyTable:
    """Hello reassemblers for many directions, with idle timeout and a bound on concurrent streams.

    Keys are caller-chosen (for example ``(flow_key, "client")``). Completed and failed keys are
    remembered (bounded) so that a repeated Hello on an already-decided stream is not re-emitted.
    """

    def __init__(self, max_streams: int = 4096, idle_timeout: float = 30.0, remember: int = 65536, **kw):
        self.max_streams = max_streams
        self.idle_timeout = idle_timeout
        self.remember = remember
        self.kw = kw
        self.active: "OrderedDict[Hashable, Tuple[HelloReassembler, float]]" = OrderedDict()
        self.decided: "OrderedDict[Hashable, str]" = OrderedDict()
        self.events: List[Tuple[Hashable, str]] = []   # (key, terminal outcome) in decision order

    def _decide(self, key: Hashable, outcome: str) -> None:
        self.decided[key] = outcome
        self.decided.move_to_end(key)
        while len(self.decided) > self.remember:
            self.decided.popitem(last=False)
        self.events.append((key, outcome))

    def add(self, key: Hashable, seq: int, payload: bytes, ts: float, isn: Optional[int] = None) -> Optional[bytes]:
        if key in self.decided:
            return None
        if key not in self.active:
            if len(self.active) >= self.max_streams:
                old_key, (old, _) = self.active.popitem(last=False)
                old.finish(INCOMPLETE_EVICTED, "stream table full")
                self._decide(old_key, old.outcome)
            self.active[key] = (HelloReassembler(**self.kw), ts)
        r, _ = self.active.pop(key)
        if isn is not None:
            r.set_isn(isn)
        out = r.add_segment(seq, payload)
        if r.done:
            self._decide(key, r.outcome)
        else:
            self.active[key] = (r, ts)
        return out

    def close(self, key: Hashable) -> Optional[str]:
        """Connection ended (FIN/RST) before the Hello completed."""
        if key in self.active:
            r, _ = self.active.pop(key)
            r.finish(INCOMPLETE_TERMINATED, "connection closed before the Hello completed")
            self._decide(key, r.outcome)
            return r.outcome
        return self.decided.get(key)

    def expire(self, now: float) -> List[Hashable]:
        expired = [k for k, (_, ts) in self.active.items() if now - ts > self.idle_timeout]
        for k in expired:
            r, _ = self.active.pop(k)
            r.finish(INCOMPLETE_TIMEOUT, "no progress within the idle timeout")
            self._decide(k, r.outcome)
        return expired

    @property
    def buffered_bytes(self) -> int:
        return sum(r.buffered_bytes for r, _ in self.active.values())
