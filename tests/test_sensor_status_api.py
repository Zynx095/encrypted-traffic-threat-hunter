"""GET /api/sensors/status must not present parser availability as a running sensor."""
import pytest
from fastapi.testclient import TestClient

from backend.main import app
import backend.event_sources.live_capture as lc


def test_sensor_status_distinguishes_adapters_from_running_sensors():
    body = TestClient(app).get("/api/sensors/status").json()
    for name in ("zeek", "suricata"):
        assert body[name]["adapter_available"] is True
        assert body[name]["ingestion_active"] is False and body[name]["connected_to_live_stream"] is False
        assert body[name]["process_managed_by_etth"] is False
        assert "available" not in body[name]
    assert "x509.log" not in body["zeek"]["supported_logs"]          # not parsed by the adapter
    assert body["ebpf"]["native_probe_included"] is False and body["ebpf"]["ingestion_active"] is False
    live = body["live_capture"]
    assert live["ingestion_active"] == (live["state"] == "CAPTURING")
    assert "not mean a sensor is running" in body["note"]


@pytest.mark.skipif(not lc.SCAPY_AVAILABLE, reason="scapy not installed")
def test_live_capture_capability_requires_a_capture_driver(monkeypatch):
    class _NotAvailableSocket:      # same class name scapy installs when wpcap/libpcap is missing
        pass
    monkeypatch.setattr(lc.scapy.all.conf, "L2listen", _NotAvailableSocket)
    cap = lc.detect_live_capture_capability()
    assert cap["available"] is False and "driver unavailable" in cap["error"]


def test_sensor_states_separate_implementation_from_running_and_validation():
    from fastapi.testclient import TestClient
    from backend.main import app
    body = TestClient(app).get("/api/sensors/status").json()
    keys = {"adapter_implemented", "configured", "dependency_installed", "sensor_running",
            "sensor_output_observed", "end_to_end_validated"}
    for name in ("live_capture", "ebpf", "zeek", "suricata"):
        st = body[name]["states"]
        assert set(st) == keys
        assert st["adapter_implemented"] is True
        assert st["end_to_end_validated"] is False          # nothing has been validated end to end
    for name in ("zeek", "suricata", "ebpf"):
        assert body[name]["states"]["sensor_output_observed"] is False
        assert body[name]["states"]["sensor_running"] is None   # not managed or monitored by ETTH
    assert body["ebpf"]["states"]["dependency_installed"] is False
