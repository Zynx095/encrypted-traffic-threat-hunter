"""Compatibility wrapper around pipeline.tls_reassembly.

The original implementation here returned a truncated buffer as "complete" when its size limit
was reached and resolved conflicting overlaps silently. Live capture and the offline reconstructor
now use ``pipeline.tls_reassembly.HelloReassembler`` directly; this class keeps the old
interface (``add_segment`` / ``completed`` / ``reset``) on top of it.
"""
from __future__ import annotations

from typing import Optional

from pipeline.tls_reassembly import DEFAULT_MAX_MESSAGE, HelloReassembler, seq_diff  # noqa: F401


class TcpStreamReassembler:
    def __init__(self, max_buffer_size: int = DEFAULT_MAX_MESSAGE):
        self.max_buffer_size = max_buffer_size
        self.reset()

    def reset(self) -> None:
        self._r = HelloReassembler(handshake_type=None, max_message=self.max_buffer_size)

    @property
    def completed(self) -> bool:
        return self._r.done

    @property
    def outcome(self) -> str:
        return self._r.outcome

    @property
    def is_tls(self) -> Optional[bool]:
        if self._r.outcome == "NO_CLIENTHELLO":
            return False
        return True if self._r.anchor is not None else None

    @property
    def out_of_order(self) -> dict:
        return self._r.unanchored

    @property
    def assembled(self) -> bytes:
        return self._r.result if self._r.result is not None else self._r._contiguous()

    def add_segment(self, seq: int, payload: bytes) -> Optional[bytes]:
        return self._r.add_segment(seq, payload)
