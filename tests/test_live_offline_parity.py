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
              "ja4", "ja4_v2", "tls_version")


def _server_hello() -> bytes:
    ext = b"\x00\x2b\x00\x02\x03\x04"
    body = b"\x03\x03" + b"\x33" * 32 + b"\x00" + b"\x13\x01" + b"\x00" + len(ext).to_bytes(2, "big") + ext
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def _frame(l3, t):
    pkt = Ether(bytes(Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / l3))
    pkt.time = T0 + t
    return pkt


def _tcp(src, dst, flags, t, payload=b"", seq=0, ack=0):
    l4 = TCP(sport=src[1], dport=dst[1], flags=flags, seq=seq, ack=ack)
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


def test_differential_clean_tls_handshake_parity(tmp_path):
    c, s = CLIENT, SERVER
    seq_c, seq_s = 1000, 5000
    ch = _client_hello()
    sh = _server_hello()
    app_client = b"\x17\x03\x03" + b"\x05" * 350
    app_server = b"\x17\x03\x03" + b"\x06" * 850

    pkts = [
        _tcp(c, s, "S", 0.000, seq=seq_c),
        _tcp(s, c, "SA", 0.020, seq=seq_s, ack=seq_c + 1),
        _tcp(c, s, "A", 0.021, seq=seq_c + 1, ack=seq_s + 1),
        _tcp(c, s, "PA", 0.030, payload=ch, seq=seq_c + 1, ack=seq_s + 1),
        _tcp(s, c, "PA", 0.060, payload=sh, seq=seq_s + 1, ack=seq_c + 1 + len(ch)),
        _tcp(c, s, "A", 0.061, seq=seq_c + 1 + len(ch), ack=seq_s + 1 + len(sh)),
        _tcp(c, s, "PA", 0.150, payload=app_client, seq=seq_c + 1 + len(ch), ack=seq_s + 1 + len(sh)),
        _tcp(s, c, "PA", 0.180, payload=app_server, seq=seq_s + 1 + len(sh), ack=seq_c + 1 + len(ch) + len(app_client)),
        _tcp(c, s, "A", 0.181, seq=seq_c + 1 + len(ch) + len(app_client), ack=seq_s + 1 + len(sh) + len(app_server)),
        _tcp(c, s, "FA", 0.500, seq=seq_c + 1 + len(ch) + len(app_client), ack=seq_s + 1 + len(sh) + len(app_server)),
        _tcp(s, c, "FA", 0.510, seq=seq_s + 1 + len(sh) + len(app_server), ack=seq_c + 1 + len(ch) + len(app_client) + 1),
        _tcp(c, s, "A", 0.511, seq=seq_c + 1 + len(ch) + len(app_client) + 1, ack=seq_s + 1 + len(sh) + len(app_server) + 1),
    ]

    offline = {_key(row["forward_endpoint"], row["start_time"]): (row, feats) for row, feats in _offline(tmp_path, pkts)}
    live = {_key(d["forward_endpoint"], d["start_time"]): d for d in _live(pkts)}

    assert set(live) == set(offline), "flow boundaries / initiators differ between live and offline"
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

    main_key = min(offline.keys(), key=lambda k: k[1])
    main_row, main_feats = offline[main_key]
    main_live = live[main_key]

    assert main_live["clienthello_present"] is True
    assert main_live["serverhello_present"] is True
    assert main_live["ja3_hash"] == main_feats["ja3_hash"]
    assert main_live["ja3s_hash"] == main_feats["ja3s_hash"]
    assert main_live["ja4"] == main_feats["ja4"]
    assert main_live["ja4_v2"] == main_feats["ja4_v2"]
    assert main_live["sni_present"] == main_feats["sni_present"]
    assert main_live["tls_version"] == main_feats["tls_version"]
    assert main_live["ja4_implementation"] == "ETTH_JA4_V1"
    assert main_feats["ja4_implementation"] == "ETTH_JA4_V1"
    assert main_live["ja4_version"] == "v1_legacy"
    assert main_feats["ja4_version"] == "v1_legacy"
    assert main_live["feature_provenance"] == "ETTH_PACKET_FEATURES"


def test_differential_fragmented_client_hello_parity(tmp_path):
    c, s = CLIENT, SERVER
    ch = _client_hello()
    assert len(ch) == 120
    split_offset = 60
    part1, part2 = ch[:split_offset], ch[split_offset:]
    sh = _server_hello()

    seq_c = 10000
    seq_s = 50000
    pkts = [
        _tcp(c, s, "S", 0.000, seq=seq_c),
        _tcp(s, c, "SA", 0.020, seq=seq_s, ack=seq_c + 1),
        _tcp(c, s, "A", 0.021, seq=seq_c + 1, ack=seq_s + 1),
        # Fragment 1 of ClientHello
        _tcp(c, s, "PA", 0.030, payload=part1, seq=seq_c + 1, ack=seq_s + 1),
        # Fragment 2 of ClientHello
        _tcp(c, s, "PA", 0.035, payload=part2, seq=seq_c + 1 + len(part1), ack=seq_s + 1),
        # ServerHello
        _tcp(s, c, "PA", 0.060, payload=sh, seq=seq_s + 1, ack=seq_c + 1 + len(ch)),
        _tcp(c, s, "A", 0.061, seq=seq_c + 1 + len(ch), ack=seq_s + 1 + len(sh)),
        # App data
        _tcp(c, s, "PA", 0.100, payload=b"\x17\x03\x03" + b"\x01" * 200, seq=seq_c + 1 + len(ch), ack=seq_s + 1 + len(sh)),
        _tcp(s, c, "PA", 0.120, payload=b"\x17\x03\x03" + b"\x02" * 400, seq=seq_s + 1 + len(sh), ack=seq_c + 1 + len(ch) + 203),
        # Teardown
        _tcp(c, s, "FA", 0.200, seq=seq_c + 1 + len(ch) + 203, ack=seq_s + 1 + len(sh) + 403),
        _tcp(s, c, "FA", 0.210, seq=seq_s + 1 + len(sh) + 403, ack=seq_c + 1 + len(ch) + 204),
        _tcp(c, s, "A", 0.211, seq=seq_c + 1 + len(ch) + 204, ack=seq_s + 1 + len(sh) + 404),
    ]

    offline = {_key(row["forward_endpoint"], row["start_time"]): (row, feats) for row, feats in _offline(tmp_path, pkts)}
    live = {_key(d["forward_endpoint"], d["start_time"]): d for d in _live(pkts)}

    assert set(live) == set(offline), "flow boundaries / initiators differ between live and offline"
    for key, (row, feats) in offline.items():
        d = live[key]
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

    main_key = min(offline.keys(), key=lambda k: k[1])
    main_row, main_feats = offline[main_key]
    main_live = live[main_key]

    assert main_live["clienthello_present"] is True
    assert main_feats["clienthello_present"] is True
    assert main_live["ja3_hash"] == main_feats["ja3_hash"]
    assert main_live["ja4"] == main_feats["ja4"]
    assert main_live["ja4_v2"] == main_feats["ja4_v2"]
    assert main_live["ja4_v2"] is not None
    assert main_live["sni_present"] == main_feats["sni_present"]
    assert main_live["tls_version"] == main_feats["tls_version"]


def test_differential_out_of_order_traffic_parity(tmp_path):
    c, s = CLIENT, SERVER
    ch = _client_hello()
    split_offset = 60
    part1, part2 = ch[:split_offset], ch[split_offset:]
    sh = _server_hello()

    seq_c = 20000
    seq_s = 60000
    pkts = [
        _tcp(c, s, "S", 0.000, seq=seq_c),
        _tcp(s, c, "SA", 0.020, seq=seq_s, ack=seq_c + 1),
        _tcp(c, s, "A", 0.021, seq=seq_c + 1, ack=seq_s + 1),
        # Out-of-order: Fragment 2 arrives at t=0.030, Fragment 1 at t=0.035
        _tcp(c, s, "PA", 0.030, payload=part2, seq=seq_c + 1 + len(part1), ack=seq_s + 1),
        _tcp(c, s, "PA", 0.035, payload=part1, seq=seq_c + 1, ack=seq_s + 1),
        # ServerHello
        _tcp(s, c, "PA", 0.060, payload=sh, seq=seq_s + 1, ack=seq_c + 1 + len(ch)),
        _tcp(c, s, "A", 0.061, seq=seq_c + 1 + len(ch), ack=seq_s + 1 + len(sh)),
        # FIN-ACK teardown
        _tcp(c, s, "FA", 0.200, seq=seq_c + 1 + len(ch), ack=seq_s + 1 + len(sh)),
        _tcp(s, c, "FA", 0.210, seq=seq_s + 1 + len(sh), ack=seq_c + 1 + len(ch) + 1),
        _tcp(c, s, "A", 0.211, seq=seq_c + 1 + len(ch) + 1, ack=seq_s + 1 + len(sh) + 1),
    ]

    offline = {_key(row["forward_endpoint"], row["start_time"]): (row, feats) for row, feats in _offline(tmp_path, pkts)}
    live = {_key(d["forward_endpoint"], d["start_time"]): d for d in _live(pkts)}

    assert set(live) == set(offline), "flow boundaries / initiators differ between live and offline"
    for key, (row, feats) in offline.items():
        d = live[key]
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

    main_key = min(offline.keys(), key=lambda k: k[1])
    main_row, main_feats = offline[main_key]
    main_live = live[main_key]

    assert main_live["clienthello_present"] is True
    assert main_feats["clienthello_present"] is True
    assert main_live["ja3_hash"] == main_feats["ja3_hash"]
    assert main_live["ja4"] == main_feats["ja4"]
    assert main_live["ja4_v2"] == main_feats["ja4_v2"]
    assert main_live["ja4_v2"] is not None


def test_differential_bidirectional_interleaved_parity(tmp_path):
    c, s = CLIENT, SERVER
    seq_c = 30000
    seq_s = 70000
    pkts = [
        _tcp(c, s, "S", 0.000, seq=seq_c),
        _tcp(s, c, "SA", 0.020, seq=seq_s, ack=seq_c + 1),
        _tcp(c, s, "A", 0.021, seq=seq_c + 1, ack=seq_s + 1),
        # Exchange 1 (burst 1)
        _tcp(c, s, "PA", 0.050, payload=b"REQ1" * 50, seq=seq_c + 1, ack=seq_s + 1),
        _tcp(s, c, "PA", 0.070, payload=b"RES1" * 100, seq=seq_s + 1, ack=seq_c + 201),
        _tcp(c, s, "PA", 0.080, payload=b"ACK1" * 25, seq=seq_c + 201, ack=seq_s + 401),
        _tcp(s, c, "PA", 0.090, payload=b"DAT1" * 150, seq=seq_s + 401, ack=seq_c + 301),
        # Idle gap of 2.0 s (> 1.0 s burst threshold)
        _tcp(c, s, "PA", 2.100, payload=b"REQ2" * 60, seq=seq_c + 301, ack=seq_s + 1001),
        _tcp(s, c, "PA", 2.120, payload=b"RES2" * 120, seq=seq_s + 1001, ack=seq_c + 541),
        # Teardown
        _tcp(c, s, "FA", 2.500, seq=seq_c + 541, ack=seq_s + 1481),
        _tcp(s, c, "FA", 2.510, seq=seq_s + 1481, ack=seq_c + 542),
        _tcp(c, s, "A", 2.511, seq=seq_c + 542, ack=seq_s + 1482),
    ]

    offline = {_key(row["forward_endpoint"], row["start_time"]): (row, feats) for row, feats in _offline(tmp_path, pkts)}
    live = {_key(d["forward_endpoint"], d["start_time"]): d for d in _live(pkts)}

    assert set(live) == set(offline), "flow boundaries / initiators differ between live and offline"
    for key, (row, feats) in offline.items():
        d = live[key]
        for f in FLOW_FEATURES:
            a, b = d[f], feats[f]
            if isinstance(b, float) and math.isnan(b):
                assert a is None or (isinstance(a, float) and math.isnan(a)), (key, f, a)
            else:
                assert a == pytest.approx(b, rel=1e-9, abs=1e-9), (key, f, a, b)

    main_key = min(offline.keys(), key=lambda k: k[1])
    main_row, main_feats = offline[main_key]
    main_live = live[main_key]

    assert main_live["forward_packets"] == main_feats["forward_packets"]
    assert main_live["reverse_packets"] == main_feats["reverse_packets"]
    assert main_live["forward_bytes"] == main_feats["forward_bytes"]
    assert main_live["reverse_bytes"] == main_feats["reverse_bytes"]
    assert main_live["number_of_bursts"] == main_feats["number_of_bursts"]
    assert main_live["idle_gap_count"] == main_feats["idle_gap_count"]


def test_differential_ja4_v2_and_version_metadata_parity(tmp_path):
    from ml.features.governance import REGISTRY, FORBIDDEN
    c, s = CLIENT, SERVER
    pkts = [
        _tcp(c, s, "S", 0.000),
        _tcp(s, c, "SA", 0.020),
        _tcp(c, s, "A", 0.021),
        _tcp(c, s, "PA", 0.030, _client_hello()),
        _tcp(s, c, "PA", 0.060, _server_hello()),
        _tcp(c, s, "FA", 0.100),
        _tcp(s, c, "FA", 0.110),
        _tcp(c, s, "A", 0.111),
    ]
    offline = {_key(row["forward_endpoint"], row["start_time"]): (row, feats) for row, feats in _offline(tmp_path, pkts)}
    live = {_key(d["forward_endpoint"], d["start_time"]): d for d in _live(pkts)}

    assert set(live) == set(offline)
    main_key = min(offline.keys(), key=lambda k: k[1])
    row, feats = offline[main_key]
    live_flow = live[main_key]

    assert live_flow["ja4"] is not None
    assert live_flow["ja4_v2"] is not None
    assert live_flow["ja4"] == feats["ja4"]
    assert live_flow["ja4_v2"] == feats["ja4_v2"]
    assert live_flow["ja4_implementation"] == "ETTH_JA4_V1"
    assert feats["ja4_implementation"] == "ETTH_JA4_V1"
    assert live_flow["ja4_version"] == "v1_legacy"
    assert feats["ja4_version"] == "v1_legacy"

    # FoxIO structure check: begins with transport/version indicator
    assert live_flow["ja4_v2"].startswith("t13")

    # Governance checks: JA4 v2 is registered in REGISTRY;
    # version metadata is in FORBIDDEN to avoid data leakage
    assert "ja4_v2" in REGISTRY
    assert "ja4_implementation" in FORBIDDEN
    assert "ja4_version" in FORBIDDEN
    assert "ja4_implementation" not in FLOW_FEATURES
    assert "ja4_version" not in FLOW_FEATURES


def test_differential_live_split_known_divergence_documentation(tmp_path):
    """
    Documented Divergence:
    Live capture imposes LIVE_MAX_FLOW_DURATION (e.g. 5.0 s) to bound latency and memory,
    marking cut flows with live_flow_split=True.
    Offline FlowReconstructor continues aggregating until idle timeout or FIN/RST.
    InferenceEngine safely skips split flows to prevent false classifications on partial connections.
    """
    c, s = CLIENT, SERVER
    src = LiveCaptureSource(max_duration=5.0)

    # First segment: 4 packets spanning 3 seconds
    pkts1 = [_tcp(c, s, "A", float(i)) for i in range(4)]
    for p in pkts1:
        src._process_packet(p)

    # Cut after max_duration has elapsed
    split_flows = src.drain_finalized(now=T0 + 5.5)
    assert len(split_flows) == 1
    assert split_flows[0]["live_flow_split"] is True
    assert split_flows[0]["total_packets"] == 4

    # Continuation packet arrives for the same connection
    pkt_cont = _tcp(c, s, "A", 6.0)
    src._process_packet(pkt_cont)
    remaining_flows = src.drain_finalized(now=T0 + 10.0, force=True)
    assert len(remaining_flows) == 1
    assert remaining_flows[0]["live_flow_split"] is True
    assert remaining_flows[0]["total_packets"] == 1

    # Offline reconstructor processes all 5 packets together
    all_pkts = pkts1 + [pkt_cont]
    offline_results = _offline(tmp_path, all_pkts)

    # Offline produces 1 contiguous flow (never split prematurely)
    assert len(offline_results) == 1
    off_row, off_feats = offline_results[0]
    assert off_row["packet_count"] == 5
    assert off_feats["total_packets"] == 5
