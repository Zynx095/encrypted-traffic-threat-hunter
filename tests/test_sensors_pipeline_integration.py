import pytest
from backend.event_sources.zeek_source import ZeekCorrelator
from backend.event_sources.suricata_source import SuricataCorrelator
from backend.event_sources.ebpf_source import EBPFEventSource
from backend.detection_pipeline import detection_pipeline
from backend.schemas import ETTHStreamEvent

def test_pipeline_integration_zeek():
    correlator = ZeekCorrelator()
    correlator.add_conn_record({
        "uid": "zeek_pipe_01",
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 45000,
        "id.resp_h": "142.250.190.78",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 1.2,
        "orig_pkts": 12,
        "resp_pkts": 18,
        "orig_bytes": 1500,
        "resp_bytes": 8000
    })
    zeek_flow = correlator.add_ssl_record({
        "uid": "zeek_pipe_01",
        "server_name": "youtube.com",
        "ja3": "51c64c77e60f3980eea90869b68c58a8",
        "ja4": "t13d1516h2_8daaf6152771_012e83626249",
        "alpn": "h2"
    })
    assert zeek_flow is not None

    event = detection_pipeline.process_flow(
        flow=zeek_flow,
        track="A_FLOW",
        stream_id="stream_zeek_test",
        sequence=1,
        mode="LIVE",
        target_id="target_youtube"
    )

    assert isinstance(event, ETTHStreamEvent)
    assert event.flow is not None
    assert event.flow.total_packets == 30
    assert event.tls is not None
    assert event.tls.ja3_hash == "51c64c77e60f3980eea90869b68c58a8"
    assert event.tls.ja4 == "t13d1516h2_8daaf6152771_012e83626249"
    assert event.attribution is not None
    assert event.detection is not None
    assert event.detection.status in ["COMPLETED", "SKIPPED"]

def test_pipeline_integration_suricata():
    correlator = SuricataCorrelator()
    correlator.add_eve_event({
        "event_type": "tls",
        "flow_id": 55443322,
        "tls": {
            "sni": "youtube.com",
            "ja3": {"hash": "b32309a26951912be7dba376398abc3b"},
            "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"
        }
    })
    suri_flow = correlator.add_eve_event({
        "event_type": "flow",
        "flow_id": 55443322,
        "src_ip": "10.0.0.5",
        "src_port": 52000,
        "dest_ip": "142.250.190.78",
        "dest_port": 443,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 8,
            "pkts_toclient": 14,
            "bytes_toserver": 900,
            "bytes_toclient": 5400,
            "age": 0.8
        }
    })
    assert suri_flow is not None

    event = detection_pipeline.process_flow(
        flow=suri_flow,
        track="E_JA4_FLOW",
        stream_id="stream_suri_test",
        sequence=2,
        mode="LIVE",
        target_id="target_youtube"
    )

    assert isinstance(event, ETTHStreamEvent)
    assert event.flow.total_packets == 22
    assert event.tls.sni_value == "youtube.com"
    assert event.tls.ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"

def test_pipeline_integration_ebpf():
    source = EBPFEventSource()
    ebpf_flow = source.parse_event({
        "saddr": "192.168.1.20",
        "daddr": "142.250.190.78",
        "sport": 49152,
        "dport": 443,
        "protocol": 6,
        "duration_ns": 1500000000,
        "bytes_sent": 1200,
        "bytes_recv": 4500,
        "packets_sent": 10,
        "packets_recv": 12,
        "pid": 2048,
        "comm": "chrome",
        "tls_sni": "youtube.com",
        "ja3": "b32309a26951912be7dba376398abc3b"
    })
    assert ebpf_flow is not None

    event = detection_pipeline.process_flow(
        flow=ebpf_flow,
        track="B_JA3",
        stream_id="stream_ebpf_test",
        sequence=3,
        mode="LIVE",
        target_id="target_youtube"
    )

    assert isinstance(event, ETTHStreamEvent)
    assert event.flow.total_packets == 22
    assert event.tls.ja3_hash == "b32309a26951912be7dba376398abc3b"
    assert event.attribution.target_id == "target_youtube"
