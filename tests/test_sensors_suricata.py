import pytest
import asyncio
from pathlib import Path

from backend.event_sources.suricata_source import SuricataEventSource, SuricataCorrelator

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "sensors"

# Synthetic, syntactically valid fingerprints (the canonical contract rejects placeholder strings).
JA3_A = "b32309a26951912be7dba376398abc3b"
JA4_A = "t13d1516h2_8daaf6152771_e5627efa2ab1"

def test_suricata_correlator_flow_tls_alert():
    correlator = SuricataCorrelator()
    flow_id = 987654321

    tls_event = {
        "event_type": "tls",
        "flow_id": flow_id,
        "tls": {
            "sni": "youtube.com",
            "version": "TLS 1.3",
            "ja3": {"hash": JA3_A},
            "ja4": JA4_A,
            "alpn": "h2"
        }
    }
    alert_event = {
        "event_type": "alert",
        "flow_id": flow_id,
        "alert": {
            "signature": "ET TROJAN Observed TLS Beaconing",
            "severity": 1
        }
    }
    flow_event = {
        "event_type": "flow",
        "flow_id": flow_id,
        "src_ip": "192.168.1.80",
        "src_port": 50123,
        "dest_ip": "142.250.190.14",
        "dest_port": 443,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 15,
            "pkts_toclient": 25,
            "bytes_toserver": 2000,
            "bytes_toclient": 12000,
            "age": 3.2,
            "state": "closed"
        }
    }

    # Ingest TLS event first
    correlator.add_eve_event(tls_event)
    # Ingest Alert event second
    correlator.add_eve_event(alert_event)
    # Ingest Flow event (finalizer)
    final_flow = correlator.add_eve_event(flow_event)

    assert final_flow is not None
    assert final_flow["flow_id"] == str(flow_id)
    assert final_flow["source_ip"] == "192.168.1.80"
    assert final_flow["destination_port"] == 443
    assert final_flow["total_packets"] == 40
    assert final_flow["total_bytes"] == 14000
    assert final_flow["sni"] == "youtube.com"
    assert final_flow["ja3_hash"] == JA3_A
    assert final_flow["ja4"] == JA4_A
    assert "ET TROJAN Observed TLS Beaconing" in final_flow["sensor_alerts"]

def test_suricata_missing_tls_handling():
    correlator = SuricataCorrelator()
    flow_event = {
        "event_type": "flow",
        "flow_id": 11223344,
        "src_ip": "10.10.10.10",
        "src_port": 4000,
        "dest_ip": "10.10.10.20",
        "dest_port": 80,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 2,
            "pkts_toclient": 0,
            "bytes_toserver": 120,
            "bytes_toclient": 0,
            "age": 0.05
        }
    }
    final_flow = correlator.add_eve_event(flow_event)
    assert final_flow is not None
    assert final_flow["clienthello_present"] is False
    assert final_flow["ja3_hash"] is None
    assert final_flow["ja4"] is None
    assert final_flow["sni"] is None

def test_suricata_source_file_ingestion():
    source = SuricataEventSource()
    eve_file = FIXTURE_DIR / "suricata_eve_synthetic.json"
    assert eve_file.exists()

    async def _test():
        await source.start()
        await source.ingest_file(eve_file)
        await source.stop()

    asyncio.run(_test())

    status = source.get_status()
    assert status["total_events_read"] >= 4
    assert status["flow_events_read"] >= 2
    assert status["tls_events_read"] >= 1
    assert status["alert_events_read"] >= 1
    assert status["malformed_lines"] >= 1  # Malformed lines safely caught
    assert status["flows_emitted"] >= 1


# ---------------------------------------------------------------- canonical contract (integration) --

def _flow_event(fid, **flow_extra):
    flow = {"pkts_toserver": 8, "pkts_toclient": 14, "bytes_toserver": 900, "bytes_toclient": 5400,
            "start": "2026-10-16T12:00:00.000000+0000", "end": "2026-10-16T12:00:00.800000+0000", "age": 0,
            "state": "closed", "reason": "timeout"}
    flow.update(flow_extra)
    return {"event_type": "flow", "flow_id": fid, "src_ip": "10.0.0.5", "src_port": 52000,
            "dest_ip": "142.250.190.78", "dest_port": 443, "proto": "TCP", "app_proto": "tls", "flow": flow}


def test_suricata_duration_uses_start_end_not_integer_age():
    flow = SuricataCorrelator().add_eve_event(_flow_event(1))
    assert flow["flow_duration"] == pytest.approx(0.8) and flow["sensor_duration_source"] == "flow.end - flow.start"
    assert flow["packets_per_second"] == pytest.approx(22 / 0.8)
    fallback = SuricataCorrelator.build_flow(_flow_event(2, start=None, end=None, age=3))
    assert fallback["flow_duration"] == 3.0 and fallback["sensor_duration_source"] == "flow.age (integer seconds)"
    none = SuricataCorrelator.build_flow(_flow_event(3, start=None, end=None, age=None))
    assert none["flow_duration"] is None and none["packets_per_second"] is None


def test_suricata_tls_semantics_and_ja3_string_derivation():
    import hashlib
    ja3_string = "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0"
    c = SuricataCorrelator()
    c.add_eve_event({"event_type": "tls", "flow_id": 7, "tls": {
        "version": "TLS 1.3", "sni": "Example.ORG", "ja3": {"string": ja3_string}, "ja4": JA4_A,
        "client_alpns": ["h2", "http/1.1"], "server_alpns": ["h2"]}})
    flow = c.add_eve_event(_flow_event(7))
    assert flow["ja3_hash"] == hashlib.md5(ja3_string.encode()).hexdigest()
    assert flow["ja3_derivation"] == "MD5_OF_REPORTED_STRING"
    assert flow["ja4_implementation"] == "FOXIO_JA4"
    assert flow["alpn_value"] == "h2" and flow["alpn_negotiated"] == "h2"     # first offered / selected
    assert "tls_version" not in flow and flow["tls_version_observed"] == "1.3"
    assert flow["sni"] == "example.org" and flow["serverhello_present"] is True


def test_suricata_serverhello_not_assumed_from_tls_event():
    c = SuricataCorrelator()
    c.add_eve_event({"event_type": "tls", "flow_id": 8, "tls": {"sni": "example.org", "version": "UNDETERMINED"}})
    flow = c.add_eve_event(_flow_event(8))
    assert flow["clienthello_present"] is True and flow["serverhello_present"] is False


def test_suricata_alerts_never_become_labels_or_model_inputs():
    from ml.features.governance import REGISTRY
    c = SuricataCorrelator()
    c.add_eve_event({"event_type": "alert", "flow_id": 9, "alert": {"signature": "ET TROJAN X", "signature_id": 1,
                                                                    "severity": 1, "category": "A Network Trojan"}})
    flow = c.add_eve_event(_flow_event(9))
    assert flow["label"] == "UNKNOWN"
    assert flow["sensor_alerts"] == ["ET TROJAN X"] and flow["sensor_alert_details"][0]["signature_id"] == 1
    assert not any(k in REGISTRY for k in flow if k.startswith("sensor_"))


def test_suricata_duplicate_and_late_events_are_not_reemitted():
    c = SuricataCorrelator()
    assert c.add_eve_event(_flow_event(10)) is not None
    assert c.add_eve_event(_flow_event(10)) is None
    assert c.add_eve_event({"event_type": "tls", "flow_id": 10, "tls": {"ja4": JA4_A}}) is None
    assert c.stats["duplicate_flow_events"] == 1 and c.stats["late_events"] == 1
    assert c._cache == {}


def test_suricata_unsupported_protocol_and_missing_endpoints():
    c = SuricataCorrelator()
    icmp = _flow_event(11)
    icmp["proto"] = "ICMP"
    assert c.add_eve_event(icmp) is None and c.stats["unsupported_protocol_events"] == 1
    no_ep = _flow_event(12)
    del no_ep["src_ip"]
    assert c.add_eve_event(no_ep) is None and c.stats["invalid_events"] == 1


def test_suricata_fixture_ingestion_counts():
    source = SuricataEventSource()

    async def _run():
        await source.start()
        await source.ingest_file(FIXTURE_DIR / "suricata_eve_synthetic.json")
        await source.stop()

    asyncio.run(_run())
    status = source.get_status()
    assert status["flows_emitted"] == 2 and status["malformed_lines"] == 1
    assert status["correlator"]["ignored_event_types"] == 1        # the stats event
