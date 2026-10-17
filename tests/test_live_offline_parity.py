"""
Live capture vs offline PCAP pipeline parity on the same synthetic packets.

The registry models were trained on features from pipeline.flow_reconstruction +
pipeline.feature_extraction. Live capture must produce the same flows (boundaries, direction)
and the same feature values for the same packets, or live scores are computed on a different
feature definition. Packets are synthetic and written to a temporary PCAP; nothing is captured.
"""
import math

import dpkt
import pytest

pytest.importorskip("scapy")
from scapy.all import Ether, ICMP, IP, IPv6, Padding, Raw, TCP, UDP, wrpcap  # noqa: E402

from backend.event_sources.live_capture import LiveCaptureSource  # noqa: E402
from ml.features.governance import FLOW_FEATURES  # noqa: E402
from pipeline.feature_extraction import build_feature_record  # noqa: E402
from pipeline.flow_reconstruction import FlowReconstructor  # noqa: E402
from tests.test_live_capture import _client_hello  # noqa: E402

T0 = 1_700_000_000.0
CLIENT, SERVER = ("192.168.1.50", 51000), ("10.0.0.1", 443)   # client sorts AFTER server as a string
TLS_FIELDS = ("clienthello_present", "serverhello_present", "sni_present", "alpn_value", "ja3_hash", "ja3s_hash",
              "ja4", "tls_version")


def _server_hello() -> bytes:
    ext = b"\x00\x2b\x00\x02\x03\x04"
    body = b"\x03\x03" + b"\x33" * 32 + b"\x00" + b"\x13\x01" + b"\x00" + len(ext).to_bytes(2, "big") + ext
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def _frame(l3, t):
    pkt = Ether(bytes(Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / l3))
    pkt.time = T0 + t
    return pkt


def _tcp(src, dst, flags, t, payload=b""):
    l4 = TCP(sport=src[1], dport=dst[1], flags=flags)
    l3 = IP(src=src[0], dst=dst[0]) / l4
    l3 = l3 / Raw(payload) if payload else l3 / Padding(b"\x00" * 6)   # short frames carry Ethernet padding
    return _frame(l3, t)


def _packets():
    c, s = CLIENT, SERVER
    return [
        _tcp(c, s, "S", 0.000), _tcp(s, c, "SA", 0.020), _tcp(c, s, "A", 0.021),
        _tcp(c, s, "PA", 0.030, _client_hello()), _tcp(s, c, "PA", 0.060, _server_hello()),
        _tcp(c, s, "A", 0.061), _tcp(c, s, "PA", 1.500, b"\x17\x03\x03" + b"\x01" * 297),
        _tcp(s, c, "PA", 1.520, b"\x17\x03\x03" + b"\x02" * 1197), _tcp(c, s, "PA", 1.530, b"\x17\x03\x03" + b"\x03" * 50),
        _tcp(c, s, "FA", 3.000), _tcp(s, c, "FA", 3.010), _tcp(c, s, "A", 3.011),     # offline splits at FIN
        _frame(IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=53000, dport=53) / Raw(b"\x00" * 30), 0.500),
        _frame(IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=53000) / Raw(b"\x00" * 90), 0.550),
        _frame(IP(src="192.168.1.50", dst="8.8.8.8") / ICMP(), 0.700),                  # ignored by both
        _frame(IPv6(src="2001:db8::2", dst="2001:db8::1") / UDP(sport=5353, dport=5353) / Raw(b"\x00" * 2) / Padding(b"\x00" * 4), 0.800),
        _tcp(c, s, "S", 200.000), _tcp(s, c, "SA", 200.020),                           # same 5-tuple after > 120 s idle
    ]


def _offline(tmp_path, packets):
    path = tmp_path / "parity.pcap"
    wrpcap(str(path), packets)
    rec = FlowReconstructor(pcap_sha256="parity-fixture")
    with open(path, "rb") as f:
        for ts, buf in dpkt.pcap.Reader(f):
            rec.process_packet(ts, buf)
    rec.flush_all()
    return [(row, build_feature_record(row)) for row in rec.completed_flows]


def _live(packets):
    src = LiveCaptureSource()
    for p in packets:
        src._process_packet(p)
    return src.drain_finalized(now=T0 + 10_000, force=True)


def _key(endpoint, start):
    return endpoint, round(start - T0, 4)


def test_live_flows_and_features_match_offline_pipeline(tmp_path):
    packets = _packets()
    offline = {_key(row["forward_endpoint"], row["start_time"]): (row, feats) for row, feats in _offline(tmp_path, packets)}
    live = {_key(d["forward_endpoint"], d["start_time"]): d for d in _live(packets)}

    assert set(live) == set(offline), "flow boundaries / initiators differ between live and offline"
    assert len(live) == 6        # TCP handshake flow, FIN-ACK flow, final ACK flow, UDP, IPv6 UDP, second TCP connection
    for key, (row, feats) in offline.items():
        d = live[key]
        assert d["reverse_endpoint"] == row["reverse_endpoint"] and d["protocol"] == row["protocol"]
        for f in FLOW_FEATURES:
            a, b = d[f], feats[f]
            if isinstance(b, float) and math.isnan(b):
                assert a is None or (isinstance(a, float) and math.isnan(a)), (key, f, a)
            else:
                assert a == pytest.approx(b, rel=1e-9, abs=1e-9), (key, f, a, b)
        for f in TLS_FIELDS:
            a, b = d[f], feats[f]
            if b is None or (isinstance(b, float) and math.isnan(b)) or b == "":
                assert a in (None, "", False) or (isinstance(a, float) and math.isnan(a)), (key, f, a, b)
            else:
                assert a == b, (key, f, a, b)


def test_live_direction_is_the_initiator_not_endpoint_order(tmp_path):
    flows = _live(_packets())
    first = min((d for d in flows if d["protocol"] == "TCP"), key=lambda d: d["start_time"])
    assert first["forward_endpoint"] == "192.168.1.50:51000"     # the client sent the SYN
    assert first["forward_packets"] == 7 and first["reverse_packets"] == 3
    assert first["ja3_hash"] and first["ja4_implementation"] == "ETTH_JA4_V1"
    assert first["feature_provenance"] == "ETTH_PACKET_FEATURES" and first["live_flow_split"] is False


def test_live_ip_length_excludes_ethernet_padding():
    flows = _live([_tcp(CLIENT, SERVER, "S", 0.0)])
    assert flows[0]["total_bytes"] == 40          # IPv4 header + TCP header; the 6 padding bytes are not counted


def test_live_split_at_max_duration_is_flagged_and_refused_by_flow_models():
    src = LiveCaptureSource(max_duration=5.0)
    for i in range(4):
        src._process_packet(_tcp(CLIENT, SERVER, "A", float(i)))
    first = src.drain_finalized(now=T0 + 5.5)              # 5.5 s after start, last packet 2.5 s ago: cut
    assert len(first) == 1 and first[0]["live_flow_split"] is True
    src._process_packet(_tcp(CLIENT, SERVER, "A", 6.0))   # continuation of the same connection
    rest = src.drain_finalized(now=T0 + 10_000, force=True)
    assert rest[0]["live_flow_split"] is True

    from backend.inference_engine import InferenceEngine
    from tests.ml_fixtures import complete_flow_record, fixture_models
    import tempfile, pathlib
    eng = InferenceEngine(autoload=False)
    with tempfile.TemporaryDirectory() as d:
        for track, (entry, model) in fixture_models(pathlib.Path(d), tracks=["A_FLOW"]).items():
            eng.install(track, entry, model)
        res = eng.predict(complete_flow_record(live_flow_split=True), track="A_FLOW")
    assert res["status"] == "SKIPPED" and "split" in res["skip_reason"]


def test_non_tcp_udp_packets_create_no_live_flows():
    flows = _live([_frame(IP(src="192.168.1.50", dst="8.8.8.8") / ICMP(), 0.0)])
    assert flows == []
