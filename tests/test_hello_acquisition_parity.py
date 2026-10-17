"""ClientHello acquisition in the offline reconstructor and live capture (synthetic packets only).

TCP_REASSEMBLY (default, live and offline) fingerprints complete Hellos only and reports why
none was produced. FIRST_SEGMENT reproduces corpus v3 exactly and is used only to rebuild it.
Every case is run through both paths and the TLS fields must agree exactly.
"""
import pytest

pytest.importorskip("scapy")

from pipeline import tls_reassembly as R  # noqa: E402
from pipeline.canonical_flow import TLS_HELLO_FIRST_SEGMENT, TLS_HELLO_TCP_REASSEMBLY  # noqa: E402
from tests.test_ja4_specification import FOXIO_JA4_REFERENCE  # noqa: E402
from tests.test_live_offline_parity import CLIENT, SERVER, _live, _offline, _tcp  # noqa: E402
from tests.test_ja4_specification import build_raw_client_hello  # noqa: E402

CH = build_raw_client_hello()
CI, SI = 70000, 90000
FIELDS = ("clienthello_present", "ja3_hash", "ja4", "ja4_v2", "clienthello_reassembly", "tls_hello_acquisition")


def _conn(client_segments, close="FA", extra=()):
    c, s = CLIENT, SERVER
    pk = [_tcp(c, s, "S", 0.0, seq=CI), _tcp(s, c, "SA", 0.01, seq=SI), _tcp(c, s, "A", 0.02, seq=CI + 1)]
    t = 0.03
    for off, data in client_segments:
        pk.append(_tcp(c, s, "PA", t, data, seq=CI + 1 + off))
        t += 0.001
    pk.extend(extra)
    pk.append(_tcp(c, s, close, 1.0, seq=CI + 1 + len(CH)))
    return pk


def _split(sizes):
    out, pos = [], 0
    for n in sizes:
        out.append((pos, CH[pos:pos + n]))
        pos += n
    out.append((pos, CH[pos:]))
    return out


def _both(tmp_path, pkts):
    off = [row for row, _ in _offline(tmp_path, pkts) if row["protocol"] == "TCP"]
    live = [d for d in _live(pkts) if d["protocol"] == "TCP"]
    assert len(off) == len(live) == 1
    o, l_ = off[0], live[0]
    for f in FIELDS:
        assert o.get(f) == l_.get(f), (f, o.get(f), l_.get(f))
    return o


def test_split_hello_is_fingerprinted_from_complete_bytes(tmp_path):
    o = _both(tmp_path, _conn(_split([40, 40, 40])))
    assert o["clienthello_reassembly"] == R.COMPLETE and o["clienthello_record_truncated"] is False
    assert o["ja4_v2"] == FOXIO_JA4_REFERENCE
    assert o["tls_hello_acquisition"] == TLS_HELLO_TCP_REASSEMBLY


def test_out_of_order_and_retransmitted_segments(tmp_path):
    parts = _split([60, 60])
    o = _both(tmp_path, _conn([parts[1], parts[0], parts[0], parts[2], parts[1]]))
    assert o["ja4_v2"] == FOXIO_JA4_REFERENCE


def test_missing_segment_then_fin_gives_no_fingerprint(tmp_path):
    parts = _split([50, 50])
    o = _both(tmp_path, _conn([parts[0], parts[2]]))
    assert o["clienthello_reassembly"] == R.INCOMPLETE_TERMINATED
    assert o["ja3_hash"] is None and o["ja4"] is None and o["ja4_v2"] is None
    assert o["clienthello_present"] is False


def test_rst_before_completion(tmp_path):
    o = _both(tmp_path, _conn(_split([50])[:1], close="R"))
    assert o["clienthello_reassembly"] == R.INCOMPLETE_TERMINATED and o["ja4_v2"] is None


def test_conflicting_overlap_gives_no_fingerprint(tmp_path):
    bad = bytearray(CH[30:90])
    bad[5] ^= 0x55
    o = _both(tmp_path, _conn([(0, CH[:60]), (30, bytes(bad)), (60, CH[60:])]))
    assert o["clienthello_reassembly"] == R.CONFLICTING_OVERLAP and o["ja4_v2"] is None


def test_flow_without_tls_reports_no_clienthello(tmp_path):
    c, s = CLIENT, SERVER
    pk = [_tcp(c, s, "S", 0.0, seq=1), _tcp(c, s, "PA", 0.1, b"GET / HTTP/1.1\r\n\r\n", seq=2), _tcp(c, s, "FA", 0.2, seq=20)]
    o = _both(tmp_path, pk)
    assert o["clienthello_reassembly"] == R.NO_CLIENTHELLO and o["ja3_hash"] is None


def test_first_segment_mode_reproduces_corpus_v3_truncation(tmp_path):
    """Corpus v3 semantics: only the first segment is parsed; the result is flagged truncated."""
    import dpkt
    from scapy.all import wrpcap
    from pipeline.flow_reconstruction import FlowReconstructor
    path = tmp_path / "v3.pcap"
    wrpcap(str(path), _conn(_split([120])))
    rec = FlowReconstructor(pcap_sha256="v3", reassemble_tls=False)
    with open(path, "rb") as f:
        for ts, buf in dpkt.pcap.Reader(f):
            rec.process_packet(ts, buf)
    rec.flush_all()
    row = next(r for r in rec.completed_flows if r["protocol"] == "TCP")
    assert row["tls_hello_acquisition"] == TLS_HELLO_FIRST_SEGMENT
    assert row["clienthello_reassembly"] is None
    if row["clienthello_present"]:
        assert row["clienthello_record_truncated"] is True
