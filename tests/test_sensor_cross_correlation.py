"""
Cross-Sensor Correlation and Validation Suite.

Validates multi-sensor ingestion, 5-tuple canonical alignment, agreement/disagreement
analysis across Zeek, Suricata, and eBPF adapters, pipeline detection uniformity, and
eBPF capability detection with graceful fallback.
"""
import pytest
from unittest.mock import patch

from backend.event_sources.zeek_source import ZeekCorrelator
from backend.event_sources.suricata_source import SuricataCorrelator
from backend.event_sources.ebpf_source import EBPFEventSource, detect_ebpf_capability
from backend.detection_pipeline import detection_pipeline
from backend.schemas import ETTHStreamEvent
from ml.features.governance import FORBIDDEN, FLOW_FEATURES

COMMON_CLIENT_IP = "192.168.1.100"
COMMON_CLIENT_PORT = 54321
COMMON_SERVER_IP = "142.250.190.78"
COMMON_SERVER_PORT = 443
COMMON_SNI = "youtube.com"
COMMON_JA3 = "b32309a26951912be7dba376398abc3b"
COMMON_JA4 = "t13d1516h2_8daaf6152771_012e83626249"
COMMON_ALPN = "h2"


def _build_zeek_flow():
    correlator = ZeekCorrelator()
    correlator.add_conn_record({
        "uid": "zeek_cross_01",
        "id.orig_h": COMMON_CLIENT_IP,
        "id.orig_p": COMMON_CLIENT_PORT,
        "id.resp_h": COMMON_SERVER_IP,
        "id.resp_p": COMMON_SERVER_PORT,
        "proto": "tcp",
        "duration": 2.4,
        "orig_pkts": 20,
        "resp_pkts": 30,
        "orig_bytes": 2500,
        "resp_bytes": 12000,
        "conn_state": "SF"
    })
    return correlator.add_ssl_record({
        "uid": "zeek_cross_01",
        "server_name": COMMON_SNI,
        "ja3": COMMON_JA3,
        "ja4": COMMON_JA4,
        "alpn": COMMON_ALPN,
        "established": True
    })


def _build_suricata_flow():
    correlator = SuricataCorrelator()
    correlator.add_eve_event({
        "event_type": "tls",
        "flow_id": 99887766,
        "src_ip": COMMON_CLIENT_IP,
        "src_port": COMMON_CLIENT_PORT,
        "dest_ip": COMMON_SERVER_IP,
        "dest_port": COMMON_SERVER_PORT,
        "proto": "TCP",
        "tls": {
            "sni": COMMON_SNI,
            "ja3": {"hash": COMMON_JA3},
            "ja4": COMMON_JA4,
            "alpn": COMMON_ALPN
        }
    })
    correlator.add_eve_event({
        "event_type": "alert",
        "flow_id": 99887766,
        "src_ip": COMMON_CLIENT_IP,
        "src_port": COMMON_CLIENT_PORT,
        "dest_ip": COMMON_SERVER_IP,
        "dest_port": COMMON_SERVER_PORT,
        "proto": "TCP",
        "alert": {
            "signature": "ET POLICY Outbound TLS Session",
            "severity": 3,
            "category": "Policy Violation"
        }
    })
    return correlator.add_eve_event({
        "event_type": "flow",
        "flow_id": 99887766,
        "src_ip": COMMON_CLIENT_IP,
        "src_port": COMMON_CLIENT_PORT,
        "dest_ip": COMMON_SERVER_IP,
        "dest_port": COMMON_SERVER_PORT,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 20,
            "pkts_toclient": 30,
            "bytes_toserver": 2500,
            "bytes_toclient": 12000,
            "start": "2026-10-17T10:00:00.000000+0000",
            "end": "2026-10-17T10:00:02.400000+0000",
            "age": 2.4,
            "state": "closed"
        }
    })


def _build_ebpf_flow():
    source = EBPFEventSource()
    return source.parse_event({
        "saddr": COMMON_CLIENT_IP,
        "daddr": COMMON_SERVER_IP,
        "sport": COMMON_CLIENT_PORT,
        "dport": COMMON_SERVER_PORT,
        "protocol": 6,
        "start_ns": 1729160000000000000,
        "end_ns": 1729160002400000000,
        "duration_ns": 2400000000,
        "bytes_sent": 2500,
        "bytes_recv": 12000,
        "packets_sent": 20,
        "packets_recv": 30,
        "pid": 5821,
        "comm": "chrome",
        "tls_sni": COMMON_SNI,
        "ja3": COMMON_JA3,
        "ja4": COMMON_JA4,
        "alpn": COMMON_ALPN
    })


def test_cross_sensor_flow_normalization_and_5tuple_matching():
    """Verifies that Zeek, Suricata, and eBPF normalize the same connection into matching 5-tuple canonical flows."""
    zeek = _build_zeek_flow()
    suricata = _build_suricata_flow()
    ebpf = _build_ebpf_flow()

    assert zeek is not None and suricata is not None and ebpf is not None

    # 5-tuple alignment
    expected_fwd = f"{COMMON_CLIENT_IP}:{COMMON_CLIENT_PORT}"
    expected_rev = f"{COMMON_SERVER_IP}:{COMMON_SERVER_PORT}"

    assert zeek["forward_endpoint"] == expected_fwd
    assert suricata["forward_endpoint"] == expected_fwd
    assert ebpf["forward_endpoint"] == expected_fwd

    assert zeek["reverse_endpoint"] == expected_rev
    assert suricata["reverse_endpoint"] == expected_rev
    assert ebpf["reverse_endpoint"] == expected_rev

    assert zeek["protocol"] == "TCP"
    assert suricata["protocol"] == "TCP"
    assert ebpf["protocol"] == "TCP"

    # Volume & duration alignment
    assert zeek["total_packets"] == 50
    assert suricata["total_packets"] == 50
    assert ebpf["total_packets"] == 50

    assert zeek["total_bytes"] == 14500
    assert suricata["total_bytes"] == 14500
    assert ebpf["total_bytes"] == 14500

    assert zeek["flow_duration"] == pytest.approx(2.4, rel=1e-3)
    assert suricata["flow_duration"] == pytest.approx(2.4, rel=1e-3)
    assert ebpf["flow_duration"] == pytest.approx(2.4, rel=1e-3)


def test_cross_sensor_agreement_and_disagreement_analysis():
    """
    Evaluates agreement and documented divergence between sensors:
    - Fingerprint & SNI agreement (JA3, JA4, SNI, ALPN)
    - Granularity divergence (Zeek wire/IP bytes vs Suricata stream vs eBPF socket context)
    - Provenance declaration prevents feature mixing
    """
    zeek = _build_zeek_flow()
    suricata = _build_suricata_flow()
    ebpf = _build_ebpf_flow()

    # Full agreement on cryptographic handshake attributes
    assert zeek["sni"] == COMMON_SNI
    assert suricata["sni"] == COMMON_SNI
    assert ebpf["sni"] == COMMON_SNI

    assert zeek["ja3_hash"] == COMMON_JA3
    assert suricata["ja3_hash"] == COMMON_JA3
    assert ebpf["ja3_hash"] == COMMON_JA3

    assert zeek["ja4"] == COMMON_JA4
    assert suricata["ja4"] == COMMON_JA4
    assert ebpf["ja4"] == COMMON_JA4

    # Documented Divergences:
    # 1. Host context: eBPF provides host process context (PID, executable name)
    assert ebpf.get("process_pid") == 5821
    assert ebpf.get("process_name") == "chrome"
    assert "process_pid" not in zeek
    assert "process_pid" not in suricata

    # 2. Alert context: Suricata attaches signature alert telemetry
    assert len(suricata.get("sensor_alerts", [])) == 1
    assert suricata["sensor_alerts"][0] == "ET POLICY Outbound TLS Session"
    assert suricata["sensor_alert_details"][0]["severity"] == 3
    assert suricata["sensor_alert_details"][0]["category"] == "Policy Violation"
    assert "sensor_alerts" not in zeek
    assert "sensor_alerts" not in ebpf

    # 3. Provenance tracking: All declare SENSOR_AGGREGATE provenance
    assert zeek["feature_provenance"] == "SENSOR_AGGREGATE"
    assert suricata["feature_provenance"] == "SENSOR_AGGREGATE"
    assert ebpf["feature_provenance"] == "SENSOR_AGGREGATE"


def test_cross_sensor_pipeline_detection_uniformity():
    """Tests that all 3 normalized sensor flows pass through the detection pipeline and produce valid ETTHStreamEvents."""
    flows = [
        ("ZEEK", _build_zeek_flow()),
        ("SURICATA", _build_suricata_flow()),
        ("EBPF", _build_ebpf_flow()),
    ]

    for sensor_name, flow in flows:
        event = detection_pipeline.process_flow(
            flow=flow,
            track="A_FLOW",
            stream_id=f"stream_{sensor_name.lower()}",
            sequence=1,
            mode="LIVE",
            target_id="target_youtube"
        )

        assert isinstance(event, ETTHStreamEvent), f"Failed for {sensor_name}"
        assert event.flow is not None
        assert event.flow.total_packets == 50
        assert event.flow.total_bytes == 14500
        assert event.tls is not None
        assert event.tls.sni_value == COMMON_SNI
        assert event.tls.ja3_hash == COMMON_JA3
        assert event.attribution is not None
        assert event.attribution.target_id == "target_youtube"
        assert event.detection is not None
        assert event.detection.status in ["COMPLETED", "SKIPPED"]


def test_cross_sensor_asynchronous_interleaved_ingestion():
    """Simulates asynchronous interleaved events arriving from different collectors."""
    zeek_corr = ZeekCorrelator()
    suri_corr = SuricataCorrelator()
    ebpf_src = EBPFEventSource()

    # Step 1: Zeek conn arrives first
    zeek_corr.add_conn_record({
        "uid": "zeek_async_01",
        "id.orig_h": COMMON_CLIENT_IP,
        "id.orig_p": COMMON_CLIENT_PORT,
        "id.resp_h": COMMON_SERVER_IP,
        "id.resp_p": COMMON_SERVER_PORT,
        "proto": "tcp",
        "duration": 1.5,
        "orig_pkts": 10,
        "resp_pkts": 15,
        "orig_bytes": 1000,
        "resp_bytes": 5000,
    })

    # Step 2: Suricata TLS arrives out-of-order before its flow record
    suri_corr.add_eve_event({
        "event_type": "tls",
        "flow_id": 776655,
        "src_ip": COMMON_CLIENT_IP,
        "src_port": COMMON_CLIENT_PORT,
        "dest_ip": COMMON_SERVER_IP,
        "dest_port": COMMON_SERVER_PORT,
        "proto": "TCP",
        "tls": {"sni": COMMON_SNI, "ja3": {"hash": COMMON_JA3}, "ja4": COMMON_JA4}
    })

    # Step 3: eBPF socket exit completes independently
    ebpf_flow = ebpf_src.parse_event({
        "saddr": COMMON_CLIENT_IP,
        "daddr": COMMON_SERVER_IP,
        "sport": COMMON_CLIENT_PORT,
        "dport": COMMON_SERVER_PORT,
        "protocol": 6,
        "duration_ns": 1500000000,
        "bytes_sent": 1000,
        "bytes_recv": 5000,
        "packets_sent": 10,
        "packets_recv": 15,
        "comm": "curl",
        "tls_sni": COMMON_SNI,
        "ja3": COMMON_JA3,
        "ja4": COMMON_JA4
    })
    assert ebpf_flow is not None

    # Step 4: Zeek SSL arrives, completing Zeek flow
    zeek_flow = zeek_corr.add_ssl_record({
        "uid": "zeek_async_01",
        "server_name": COMMON_SNI,
        "ja3": COMMON_JA3,
        "ja4": COMMON_JA4
    })
    assert zeek_flow is not None

    # Step 5: Suricata flow arrives, completing Suricata flow
    suri_flow = suri_corr.add_eve_event({
        "event_type": "flow",
        "flow_id": 776655,
        "src_ip": COMMON_CLIENT_IP,
        "src_port": COMMON_CLIENT_PORT,
        "dest_ip": COMMON_SERVER_IP,
        "dest_port": COMMON_SERVER_PORT,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 10,
            "pkts_toclient": 15,
            "bytes_toserver": 1000,
            "bytes_toclient": 5000,
            "start": "2026-10-17T10:00:00.000000+0000",
            "end": "2026-10-17T10:00:01.500000+0000",
            "age": 1.5
        }
    })
    assert suri_flow is not None

    # Verify no state collision between adapters
    assert zeek_flow["ja3_hash"] == suri_flow["ja3_hash"] == ebpf_flow["ja3_hash"] == COMMON_JA3
    assert zeek_flow["total_packets"] == suri_flow["total_packets"] == ebpf_flow["total_packets"] == 25


def test_ebpf_capability_detection_and_fallback():
    """Validates capability detection on current OS and simulates Linux capability checks."""
    cap = detect_ebpf_capability()
    assert "adapter_available" in cap
    assert cap["adapter_available"] is True
    assert cap["native_probe_included"] is False

    # Simulate non-Linux OS fallback
    with patch("platform.system", return_value="Windows"):
        win_cap = detect_ebpf_capability()
        assert win_cap["available"] is False
        assert win_cap["btf_available"] is False
        assert "require Linux" in win_cap["reason"]

    # Simulate Linux OS with BTF and root privileges
    with patch("platform.system", return_value="Linux"), \
         patch("os.path.exists", return_value=True), \
         patch("os.geteuid", return_value=0, create=True):
        linux_cap_root = detect_ebpf_capability()
        assert linux_cap_root["available"] is True
        assert linux_cap_root["btf_available"] is True
        assert linux_cap_root["privileges"] == "root"
        assert linux_cap_root["reason"] is None

    # Simulate Linux OS unprivileged
    with patch("platform.system", return_value="Linux"), \
         patch("os.path.exists", return_value=True), \
         patch("os.geteuid", return_value=1000, create=True):
        linux_cap_unpriv = detect_ebpf_capability()
        assert linux_cap_unpriv["available"] is False
        assert "Root" in linux_cap_unpriv["reason"]


def test_sensor_metadata_governance_isolation():
    """Ensures sensor-specific auxiliary metadata cannot contaminate model matrices."""
    # Sensor auxiliary metadata fields must either be in FORBIDDEN or never appear in FLOW_FEATURES
    sensor_specific_fields = [
        "process_pid", "process_name", "comm", "pid", "alert_count",
        "highest_severity", "alert_categories", "uid", "flow_id"
    ]
    for field in sensor_specific_fields:
        assert field not in FLOW_FEATURES, f"{field} leaked into FLOW_FEATURES"
