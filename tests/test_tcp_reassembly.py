"""
Comprehensive unit and integration tests for bounded TCP stream reassembly.
Tests single-segment, multi-segment, out-of-order, retransmission/overlap,
sequence wraparound, memory bounds, and fingerprint equality.
"""
import pytest
from backend.event_sources.tcp_reassembly import TcpStreamReassembler, seq_diff
from pipeline.tls_fingerprinting import (
    generate_ja3,
    generate_ja4,
    generate_ja4_foxio,
    parse_client_hello
)
from tests.test_ja4_specification import build_raw_client_hello, FOXIO_JA4_REFERENCE, ETTH_JA4_V1_REFERENCE


def test_seq_diff_wraparound():
    """Verify 32-bit sequence number arithmetic."""
    assert seq_diff(100, 50) == 50
    assert seq_diff(50, 100) == -50
    assert seq_diff(0, 0) == 0
    # Wraparound around 2^32
    assert seq_diff(10, 0xFFFFFFFF) == 11
    assert seq_diff(0xFFFFFFFF, 10) == -11
    assert seq_diff(0x80000000, 0) == -2147483648


def test_single_segment_client_hello():
    """Single-segment ClientHello completes immediately."""
    raw = build_raw_client_hello()
    reassembler = TcpStreamReassembler()
    res = reassembler.add_segment(seq=1000, payload=raw)
    assert res is not None
    assert res == raw
    assert reassembler.completed is True


def test_two_segments_in_order():
    """ClientHello split across 2 segments arrives in order."""
    raw = build_raw_client_hello()
    split_point = 100
    seg1 = raw[:split_point]
    seg2 = raw[split_point:]

    reassembler = TcpStreamReassembler()
    res1 = reassembler.add_segment(seq=5000, payload=seg1)
    assert res1 is None
    assert reassembler.completed is False

    res2 = reassembler.add_segment(seq=5000 + split_point, payload=seg2)
    assert res2 is not None
    assert res2 == raw
    assert reassembler.completed is True


def test_two_segments_out_of_order():
    """ClientHello split across 2 segments arrives out of order (seg 2 before seg 1)."""
    raw = build_raw_client_hello()
    split_point = 120
    seg1 = raw[:split_point]
    seg2 = raw[split_point:]

    reassembler = TcpStreamReassembler()
    # Segment 2 arrives first
    res1 = reassembler.add_segment(seq=2000 + split_point, payload=seg2)
    assert res1 is None
    assert reassembler.completed is False

    # Segment 1 arrives second
    res2 = reassembler.add_segment(seq=2000, payload=seg1)
    assert res2 is not None
    assert res2 == raw
    assert reassembler.completed is True


def test_n_segments_fragmentation():
    """ClientHello fragmented across many small segments (e.g. 50 bytes each)."""
    raw = build_raw_client_hello()
    chunk_size = 45
    chunks = [raw[i:i + chunk_size] for i in range(0, len(raw), chunk_size)]

    reassembler = TcpStreamReassembler()
    seq = 10000
    res = None
    for chunk in chunks:
        res = reassembler.add_segment(seq=seq, payload=chunk)
        seq += len(chunk)

    assert res is not None
    assert res == raw
    assert reassembler.completed is True


def test_retransmission_and_overlap():
    """Handles retransmitted and overlapping TCP segments without duplicating bytes."""
    raw = build_raw_client_hello()
    seg1 = raw[:80]
    seg2_overlapping = raw[60:150]  # Overlaps 20 bytes with seg1
    seg3 = raw[150:]

    reassembler = TcpStreamReassembler()
    assert reassembler.add_segment(seq=1000, payload=seg1) is None
    # Duplicate segment 1
    assert reassembler.add_segment(seq=1000, payload=seg1) is None
    # Overlapping segment 2
    assert reassembler.add_segment(seq=1060, payload=seg2_overlapping) is None
    # Final segment
    res = reassembler.add_segment(seq=1150, payload=seg3)

    assert res is not None
    assert res == raw
    assert reassembler.completed is True


def test_fingerprint_equality_across_fragmentation():
    """Verify JA3, JA4 v1, and JA4 v2 extracted from fragmented stream match ground truth."""
    raw = build_raw_client_hello()
    # Fragment into 3 irregular pieces
    p1 = raw[:50]
    p2 = raw[50:180]
    p3 = raw[180:]

    reassembler = TcpStreamReassembler()
    # Deliver out of order: p2, p1, p3
    reassembler.add_segment(seq=500 + 50, payload=p2)
    reassembler.add_segment(seq=500, payload=p1)
    reassembled = reassembler.add_segment(seq=500 + 180, payload=p3)

    assert reassembled == raw
    parsed = parse_client_hello(reassembled)
    assert not parsed.get("error")

    ja3_str, ja3_hash = generate_ja3(parsed)
    assert ja3_hash is not None
    assert generate_ja4(parsed, version="v1_legacy") == ETTH_JA4_V1_REFERENCE
    assert generate_ja4_foxio(parsed) == FOXIO_JA4_REFERENCE


def test_non_tls_payload_fast_rejection():
    """Non-TLS payload (e.g. HTTP GET) is rejected immediately with no memory retention."""
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reassembler = TcpStreamReassembler()
    res = reassembler.add_segment(seq=1000, payload=http_payload)
    assert res is None
    assert reassembler.is_tls is False
    assert reassembler.completed is True
    assert len(reassembler.out_of_order) == 0


def test_bounded_buffer_limit():
    """Enforces maximum buffer capacity (e.g. 16 KB) to prevent memory exhaustion."""
    max_buf = 512
    reassembler = TcpStreamReassembler(max_buffer_size=max_buf)
    # Start with valid TLS handshake record header declaring large record (e.g. 10000 bytes)
    header = b"\x16\x03\x01\x27\x10\x01\x00\x27\x0c"  # 10000 byte record
    reassembler.add_segment(seq=1000, payload=header)

    # Flood with segments up to and beyond max_buf
    chunk = b"\x00" * 100
    for i in range(10):
        reassembler.add_segment(seq=1000 + len(header) + i * 100, payload=chunk)

    assert len(reassembler.assembled) <= max_buf
    assert reassembler.completed is True


def test_seq_wraparound_reassembly():
    """Reassembles segments correctly across 32-bit sequence number wraparound boundary."""
    raw = build_raw_client_hello()
    seg1 = raw[:100]
    seg2 = raw[100:]

    reassembler = TcpStreamReassembler()
    # Sequence starts 50 bytes before 2^32 boundary
    start_seq = 0xFFFFFFCE  # 2^32 - 50
    seg2_seq = (start_seq + 100) & 0xFFFFFFFF  # Wraps to 50

    # Deliver seg 2 first
    reassembler.add_segment(seq=seg2_seq, payload=seg2)
    # Deliver seg 1 second
    res = reassembler.add_segment(seq=start_seq, payload=seg1)

    assert res is not None
    assert res == raw
