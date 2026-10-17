import pytest
import asyncio
from pathlib import Path

from backend.event_sources.ebpf_source import EBPFEventSource, detect_ebpf_capability

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "sensors"

def test_ebpf_capability_detection():
    cap = detect_ebpf_capability()
    assert "available" in cap
    assert "os" in cap
    # On Windows test runner, must safely report OS without throwing exceptions
    assert cap["os"] in ["Windows", "Linux", "Darwin"]

def test_ebpf_event_parsing_and_contract_validation():
    source = EBPFEventSource()
    raw_event = {
        "saddr": "192.168.1.100",
        "daddr": "104.16.12.1",
        "sport": 54321,
        "dport": 443,
        "protocol": 6,
        "duration_ns": 2000000000, # 2.0 seconds
        "bytes_sent": 1500,
        "bytes_recv": 6000,
        "packets_sent": 10,
        "packets_recv": 15,
        "pid": 4321,
        "comm": "curl",
        "tls_sni": "api.example.com",
        "ja3": "myja3hash",
        "ja4": "t13d1516h2_ebpf",
        "alpn": "h2"
    }
    flow = source.parse_event(raw_event)
    assert flow is not None
    assert flow["source_ip"] == "192.168.1.100"
    assert flow["destination_ip"] == "104.16.12.1"
    assert flow["flow_duration"] == 2.0
    assert flow["total_packets"] == 25
    assert flow["total_bytes"] == 7500
    assert flow["sni"] == "api.example.com"
    assert flow["ja3_hash"] == "myja3hash"
    assert flow["ja4"] == "t13d1516h2_ebpf"
    assert flow["process_pid"] == 4321
    assert flow["process_name"] == "curl"

def test_ebpf_missing_tls_and_malformed_handling():
    source = EBPFEventSource()
    # Missing TLS fields
    raw_event = {
        "saddr": "10.0.0.1",
        "daddr": "10.0.0.2",
        "sport": 1234,
        "dport": 80,
        "protocol": 6,
        "bytes_sent": 100,
        "bytes_recv": 200
    }
    flow = source.parse_event(raw_event)
    assert flow is not None
    assert flow["clienthello_present"] is False
    assert flow["ja3_hash"] is None
    assert flow["ja4"] is None
    assert flow["sni"] is None

    # Malformed event (missing destination)
    malformed = {"saddr": "1.1.1.1"}
    bad_flow = source.parse_event(malformed)
    assert bad_flow is None
    assert source.malformed_events == 1
