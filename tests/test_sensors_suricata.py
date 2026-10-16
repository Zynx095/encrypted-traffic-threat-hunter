import pytest
import asyncio
from pathlib import Path

from backend.event_sources.suricata_source import SuricataEventSource, SuricataCorrelator

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "sensors"

def test_suricata_correlator_flow_tls_alert():
    correlator = SuricataCorrelator()
    flow_id = 987654321

    tls_event = {
        "event_type": "tls",
        "flow_id": flow_id,
        "tls": {
            "sni": "youtube.com",
            "version": "TLS 1.3",
            "ja3": {"hash": "ja3hash123"},
            "ja4": "t13d1516h2_suricata",
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
    assert final_flow["ja3_hash"] == "ja3hash123"
    assert final_flow["ja4"] == "t13d1516h2_suricata"
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
