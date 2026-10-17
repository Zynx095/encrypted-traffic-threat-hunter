import pytest
import asyncio
from pathlib import Path

from backend.event_sources.ebpf_source import EBPFEventSource, detect_ebpf_capability

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "sensors"

# Synthetic, syntactically valid fingerprints (the canonical contract rejects placeholder strings).
JA3_A = "6734f37431670b3ab4292b8f60f29984"
JA4_A = "t13d1516h2_8daaf6152771_e5627efa2ab1"

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
        "ja3": JA3_A,
        "ja4": JA4_A,
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
    assert flow["ja3_hash"] == JA3_A
    assert flow["ja4"] == JA4_A
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


# ---------------------------------------------------------------- canonical contract (integration) --

def _event(**extra):
    ev = {"saddr": "10.0.0.1", "daddr": "10.0.0.2", "sport": 40000, "dport": 443, "protocol": 6,
          "bytes_sent": 100, "bytes_recv": 200, "packets_sent": 2, "packets_recv": 3}
    ev.update(extra)
    return ev


def test_ebpf_capability_separates_adapter_from_native_probes():
    cap = detect_ebpf_capability()
    assert cap["adapter_available"] is True and cap["native_probe_included"] is False
    if cap["os"] != "Linux":
        assert cap["available"] is False and cap["reason"]


def test_ebpf_missing_duration_is_not_zero_and_gives_no_rate():
    flow = EBPFEventSource().parse_event(_event())
    assert flow["flow_duration"] is None and flow["packets_per_second"] is None
    assert flow["total_packets"] == 5 and flow["byte_count_semantics"] == "UNKNOWN"
    timed = EBPFEventSource().parse_event(_event(start_ns=1_000_000_000, end_ns=1_500_000_000))
    assert timed["flow_duration"] == pytest.approx(0.5) and timed["packets_per_second"] == pytest.approx(10.0)


def test_ebpf_ja3_string_in_hash_field_and_undeclared_ja4_implementation():
    s = "771,4865-4866,0-23,29,0"
    flow = EBPFEventSource().parse_event(_event(ja3_hash=s, ja4=JA4_A))
    import hashlib
    assert flow["ja3_hash"] == hashlib.md5(s.encode()).hexdigest() and flow["ja3_derivation"] == "MD5_OF_REPORTED_STRING"
    assert flow["ja4_implementation"] == "UNKNOWN"
    declared = EBPFEventSource().parse_event(_event(ja4=JA4_A, ja4_implementation="ETTH_JA4_V1"))
    assert declared["ja4_implementation"] == "ETTH_JA4_V1"
    assert "tls_version" not in flow and "alpn_value" not in flow


def test_ebpf_fixture_file_is_parsed_without_fabrication():
    source = EBPFEventSource()
    flows = [f for f in (source.parse_line(l) for l in (FIXTURE_DIR / "ebpf_synthetic.json").read_text("utf-8").splitlines()) if f]
    assert len(flows) == 2 and source.malformed_events == 1
    # The fixture's ja3_hash ('771,4865-4866,0-23') is an incomplete JA3 string: rejected, not copied.
    assert flows[0]["ja3_hash"] is None and flows[0]["ja3_rejected_reason"]
    assert flows[0]["flow_duration"] == pytest.approx(1.5)
    assert flows[1]["protocol"] == "UDP" and flows[1]["clienthello_present"] is False


def test_ebpf_invalid_ports_protocols_and_duplicates():
    source = EBPFEventSource()
    assert source.parse_event(_event(sport=70000)) is None and source.malformed_events == 1
    assert source.parse_event(_event(protocol=1)) is None and source.unsupported_events == 1
    assert source.parse_event(_event(flow_id="f1")) is not None
    assert source.parse_event(_event(flow_id="f1")) is None and source.duplicate_events == 1
