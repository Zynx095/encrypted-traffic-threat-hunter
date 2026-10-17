"""Bounded ClientHello reassembly (pipeline.tls_reassembly). All inputs are synthetic.

Each test asserts the outcome and, where one is produced, that the record is byte-identical to
the original ClientHello and fingerprints to the FoxIO reference value.
"""

from pipeline import tls_reassembly as R
from pipeline.tls_fingerprinting import generate_ja4_foxio, parse_client_hello
from tests.test_ja4_specification import FOXIO_JA4_REFERENCE, build_raw_client_hello

CH = build_raw_client_hello()


def chunks(data, sizes):
    out, pos = [], 0
    for n in sizes:
        out.append((pos, data[pos:pos + n]))
        pos += n
    if pos < len(data):
        out.append((pos, data[pos:]))
    return out


def feed(r, base, parts):
    results = [r.add_segment((base + off) & 0xFFFFFFFF, data) for off, data in parts]
    return [x for x in results if x is not None]


def assert_reference(rec):
    assert rec == CH
    assert generate_ja4_foxio(parse_client_hello(rec)) == FOXIO_JA4_REFERENCE


def test_01_single_segment():
    r = R.HelloReassembler()
    assert_reference(r.add_segment(1000, CH))
    assert r.outcome == R.COMPLETE and r.buffered_bytes == 0


def test_02_two_segments():
    r = R.HelloReassembler()
    a, b = chunks(CH, [60])
    assert r.add_segment(5000, a[1]) is None and r.outcome == R.PENDING
    assert_reference(r.add_segment(5000 + b[0], b[1]))


def test_03_many_segments_across_seq_wrap():
    r = R.HelloReassembler()
    out = feed(r, 0xFFFFFFF0, chunks(CH, [7] * 30))
    assert len(out) == 1
    assert_reference(out[0])


def test_04_out_of_order():
    r = R.HelloReassembler()
    r.set_isn(99)                                    # SYN seen: offset 0 is seq 100
    parts = chunks(CH, [40, 40, 40])
    assert feed(r, 100, list(reversed(parts))[:-1]) == []
    assert_reference(r.add_segment(100, parts[0][1]))


def test_05_identical_retransmission_absorbed():
    r = R.HelloReassembler()
    a, b = chunks(CH, [80])
    r.add_segment(1, a[1])
    r.add_segment(1, a[1])
    assert len(r.segments) == 1 and r.outcome == R.PENDING
    assert_reference(r.add_segment(1 + b[0], b[1]))


def test_06_partial_retransmission():
    r = R.HelloReassembler()
    r.add_segment(10, CH[:50])
    r.add_segment(10 + 30, CH[30:90])               # overlaps 30..50 with identical bytes
    assert_reference(r.add_segment(10 + 90, CH[90:]))


def test_07_duplicate_complete_handshake_reported_once():
    r = R.HelloReassembler()
    assert_reference(r.add_segment(7, CH))
    assert r.add_segment(7, CH) is None
    assert r.add_segment(7 + len(CH), CH) is None
    assert r.outcome == R.COMPLETE


def test_08_valid_overlapping_segments():
    r = R.HelloReassembler()
    r.add_segment(0, CH[:100])
    r.add_segment(20, CH[20:140])
    assert_reference(r.add_segment(60, CH[60:]))


def test_09_conflicting_overlap_fails_closed():
    r = R.HelloReassembler()
    r.add_segment(0, CH[:100])
    bad = bytearray(CH[50:150])
    bad[10] ^= 0xFF
    assert r.add_segment(50, bytes(bad)) is None
    assert r.outcome == R.CONFLICTING_OVERLAP and r.result is None
    assert r.add_segment(100, CH[100:]) is None     # terminal: no later fingerprint


def test_10_missing_segment_then_timeout():
    t = R.ReassemblyTable(idle_timeout=5)
    t.add("f1", 0, CH[:50], ts=0.0)
    t.add("f1", 100, CH[100:], ts=1.0)              # gap 50..100 never arrives
    assert t.expire(now=3.0) == []
    assert t.expire(now=10.0) == ["f1"]
    assert t.decided["f1"] == R.INCOMPLETE_TIMEOUT and t.buffered_bytes == 0
    assert t.add("f1", 50, CH[50:100], ts=11.0) is None   # late fill does not resurrect it


def test_11_termination_before_completion():
    t = R.ReassemblyTable()
    t.add("f1", 0, CH[:70], ts=0.0)
    assert t.close("f1") == R.INCOMPLETE_TERMINATED
    assert t.add("f1", 70, CH[70:], ts=0.1) is None


def test_12_malformed_record_length():
    r = R.HelloReassembler()
    bad = CH[:3] + (0).to_bytes(2, "big") + CH[5:]
    assert r.add_segment(0, bad) is None and r.outcome == R.MALFORMED
    r2 = R.HelloReassembler()
    assert r2.add_segment(0, CH[:3] + (40000).to_bytes(2, "big") + CH[5:]) is None
    assert r2.outcome == R.MALFORMED


def test_13_malformed_handshake_length():
    r = R.HelloReassembler()
    bad = CH[:6] + (10).to_bytes(3, "big") + CH[9:]
    assert r.add_segment(0, bad) is None and r.outcome == R.MALFORMED


def test_14_concurrent_connections_are_independent():
    t = R.ReassemblyTable()
    other = build_raw_client_hello(sni_hostname=None)
    out = []
    for (oa, a), (ob, b) in zip(chunks(CH, [50, 50, 50]), chunks(other, [50, 50, 50])):
        out.append(("A", t.add("A", 1000 + oa, a, 0.0)))
        out.append(("B", t.add("B", 9000 + ob, b, 0.0)))
    done = {k: v for k, v in out if v is not None}
    assert_reference(done["A"])
    assert done["B"] == other


def test_15_eviction_under_stream_limit():
    t = R.ReassemblyTable(max_streams=2)
    t.add("a", 0, CH[:40], 0.0)
    t.add("b", 0, CH[:40], 0.0)
    t.add("c", 0, CH[:40], 0.0)
    assert set(t.active) == {"b", "c"}
    assert t.decided["a"] == R.INCOMPLETE_EVICTED


def test_16_excessive_declared_length_is_unsupported_not_buffered():
    r = R.HelloReassembler(max_message=4096)
    huge = b"\x16\x03\x01\x40\x00" + b"\x01" + (60000).to_bytes(3, "big") + b"\x03\x03" + b"\x00" * 100
    assert r.add_segment(0, huge) is None
    assert r.outcome == R.UNSUPPORTED and r.buffered_bytes == 0


def test_17_repeated_capture_of_same_handshake_on_table():
    t = R.ReassemblyTable()
    assert_reference(t.add("k", 0, CH, 0.0))
    assert t.add("k", 0, CH, 0.5) is None
    assert [e for e in t.events if e[0] == "k"] == [("k", R.COMPLETE)]


def test_18_valid_hello_after_malformed_flow():
    t = R.ReassemblyTable()
    t.add("bad", 0, b"\x16\x03\x01\x00\x00garbage", 0.0)
    assert t.decided["bad"] == R.MALFORMED
    assert_reference(t.add("good", 0, CH, 0.1))


def test_19_malformed_flow_does_not_affect_interleaved_flow():
    t = R.ReassemblyTable()
    parts = chunks(CH, [64, 64])
    t.add("good", 0, parts[0][1], 0.0)
    t.add("bad", 0, b"\x16\x03\x03\x00\x05\x02\x00\x00\x01\x00", 0.0)     # ServerHello type
    assert t.decided["bad"] == R.NO_CLIENTHELLO
    t.add("good", parts[1][0], parts[1][1], 0.0)
    assert_reference(t.add("good", parts[2][0], parts[2][1], 0.0))


def test_20_resources_released_after_completion_and_timeout():
    t = R.ReassemblyTable(idle_timeout=1)
    t.add("done", 0, CH, 0.0)
    t.add("stalled", 0, CH[:30], 0.0)
    assert "done" not in t.active and t.buffered_bytes == 30
    t.expire(5.0)
    assert t.active == {} and t.buffered_bytes == 0


def test_non_tls_stream_is_no_clienthello():
    r = R.HelloReassembler()
    r.set_isn(0)
    assert r.add_segment(1, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None
    assert r.outcome == R.NO_CLIENTHELLO


def test_lost_first_segment_detected_when_syn_seen():
    r = R.HelloReassembler()
    r.set_isn(0)
    for off, data in chunks(CH, [50])[1:]:
        assert r.add_segment(1 + off, data) is None
    assert r.outcome == R.PENDING
    assert r.finish(R.INCOMPLETE_TIMEOUT) == R.INCOMPLETE_TIMEOUT


def test_hello_split_across_two_tls_records():
    msg = CH[5:]
    rec = b"\x16\x03\x01" + (100).to_bytes(2, "big") + msg[:100] + \
          b"\x16\x03\x01" + (len(msg) - 100).to_bytes(2, "big") + msg[100:]
    r = R.HelloReassembler()
    assert_reference(r.add_segment(0, rec))


def test_server_hello_mode_completes_inside_a_larger_record():
    sh_body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x13\x01" + b"\x00" + b"\x00\x00"
    sh = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
    cert = b"\x0b\x00\x00\x04\x00\x00\x00\x00"
    rec = b"\x16\x03\x03" + (len(sh) + len(cert)).to_bytes(2, "big") + sh + cert
    r = R.HelloReassembler(handshake_type=0x02)
    out = r.add_segment(0, rec[:len(sh) + 5 + 2])   # certificate not yet arrived
    assert out == b"\x16\x03\x03" + len(sh).to_bytes(2, "big") + sh
