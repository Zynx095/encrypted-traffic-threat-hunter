"""
Cross-phase integration: Phase 11 sensor adapters -> canonical flow -> Phase 8-10 detection
pipeline (registry-style inference) -> canonical event -> WebSocket delivery.

All inputs are clearly labelled synthetic fixtures (data/fixtures/sensors) or synthetic models
(tests/ml_fixtures.py). These tests verify software contracts only; they are not evidence of
detection quality.
"""
import asyncio
import json
from pathlib import Path

import pytest

import backend.detection_pipeline as dp
from backend.detection_pipeline import DetectionPipeline
from backend.event_sources.ebpf_source import EBPFEventSource
from backend.event_sources.suricata_source import SuricataEventSource
from backend.event_sources.zeek_source import ZeekCorrelator, ZeekEventSource
from backend.inference_engine import InferenceEngine
from backend.schemas import ETTHStreamEvent
from backend.ws_manager import ConnectionManager
from tests.ml_fixtures import complete_flow_record, fixture_models

FIXTURES = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "sensors"
JA3_A = "6734f37431670b3ab4292b8f60f29984"
JA4_FOXIO = "t13d1516h2_8daaf6152771_e5627efa2ab1"


@pytest.fixture()
def engine(tmp_path, monkeypatch):
    eng = InferenceEngine(autoload=False)
    for track, (entry, model) in fixture_models(tmp_path).items():
        eng.install(track, entry, model)
    monkeypatch.setattr(dp, "inference_engine", eng)
    return eng


def _zeek_flows():
    source = ZeekEventSource()

    async def run():
        await source.start()
        await source.ingest_file(FIXTURES / "zeek_ssl_synthetic.json", log_hint="ssl")
        await source.ingest_file(FIXTURES / "zeek_conn_synthetic.json", log_hint="conn")
        await source.stop()
        return [source.queue.get_nowait() for _ in range(source.queue.qsize())]

    return asyncio.run(run())


def _suricata_flows():
    source = SuricataEventSource()

    async def run():
        await source.ingest_file(FIXTURES / "suricata_eve_synthetic.json")
        return [source.queue.get_nowait() for _ in range(source.queue.qsize())]

    return asyncio.run(run())


def _ebpf_flows():
    source = EBPFEventSource()
    lines = (FIXTURES / "ebpf_synthetic.json").read_text("utf-8").splitlines()
    return [f for f in (source.parse_line(l) for l in lines) if f]


def _strict_json(event: ETTHStreamEvent) -> dict:
    payload = event.model_dump()
    text = json.dumps(payload, allow_nan=False)        # browsers reject NaN/Infinity in JSON
    ETTHStreamEvent.model_validate(json.loads(text))
    return payload


SOURCES = {"ZEEK": _zeek_flows, "SURICATA": _suricata_flows, "EBPF": _ebpf_flows}


@pytest.mark.parametrize("sensor", list(SOURCES))
def test_sensor_flows_reach_pipeline_with_provenance_and_valid_events(engine, sensor):
    flows = SOURCES[sensor]()
    assert flows
    for i, flow in enumerate(flows, start=1):
        for track in ("A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"):
            ev = DetectionPipeline().process_flow(flow, track=track, stream_id=f"s-{sensor}", sequence=i, mode="LIVE")
            payload = _strict_json(ev)
            assert payload["provenance"]["sensor"]["sensor_type"] == sensor
            assert payload["provenance"]["sensor"]["feature_provenance"] == "SENSOR_AGGREGATE"
            assert payload["provenance"]["label_ground_truth"] == "UNKNOWN"
            assert payload["detection"]["status"] in ("COMPLETED", "SKIPPED")
            if track in ("A_FLOW", "D_JA3_FLOW", "E_JA4_FLOW"):
                # Sensor counters never feed models trained on ETTH packet features.
                assert payload["detection"]["status"] == "SKIPPED"
                assert payload["detection"]["prediction"] == "UNKNOWN"


def test_zeek_ja3_is_scored_by_the_model_and_foxio_ja4_is_refused(engine):
    flow = next(f for f in _zeek_flows() if f["ja3_hash"] and f["ja4"])
    b = DetectionPipeline().process_flow(flow, track="B_JA3", stream_id="s", sequence=1, mode="LIVE")
    assert b.detection.status == "COMPLETED"
    assert b.detection.inference_type == "REGISTERED_RESEARCH_PILOT_MODEL"
    assert b.detection.model_id == "fixture-b_ja3" and 0.0 <= b.detection.threat_score <= 1.0
    assert "UNSEEN_CATEGORY:ja3_hash" in b.detection.ood_flags     # sensor JA3 outside the fixture vocabulary
    c = DetectionPipeline().process_flow(flow, track="C_JA4", stream_id="s", sequence=2, mode="LIVE")
    assert c.detection.status == "SKIPPED" and "FOXIO_JA4" in c.detection.skip_reason


def test_suricata_alerts_are_context_not_prediction(engine):
    flow = next(f for f in _suricata_flows() if f["sensor_alerts"])
    quiet = {**flow, "sensor_alerts": [], "sensor_alert_details": []}
    loud = DetectionPipeline().process_flow(flow, track="B_JA3", stream_id="s", sequence=1, mode="LIVE")
    calm = DetectionPipeline().process_flow(quiet, track="B_JA3", stream_id="s", sequence=2, mode="LIVE")
    assert loud.provenance.sensor.external_alert_signatures == ["ET POLICY Suspicious Inbound TLS Session"]
    assert loud.provenance.label_ground_truth == "UNKNOWN"
    assert loud.detection.threat_score == calm.detection.threat_score
    assert loud.detection.prediction == calm.detection.prediction


def test_unobserved_fields_are_declared_not_silently_zero(engine):
    flow = EBPFEventSource().parse_event({"saddr": "10.0.0.1", "daddr": "10.0.0.2", "sport": 40000, "dport": 443,
                                          "protocol": 6, "packets_sent": 1, "packets_recv": 1})
    ev = DetectionPipeline().process_flow(flow, track="A_FLOW", stream_id="s", sequence=1, mode="LIVE")
    assert {"flow_duration", "total_bytes", "packets_per_second", "bytes_per_second"} <= set(ev.flow.unobserved_fields)
    assert "total_packets" not in ev.flow.unobserved_fields


def test_out_of_order_and_duplicate_sensor_records_yield_one_event(engine):
    correlator = ZeekCorrelator()
    ssl = {"uid": "C1", "ja3": JA3_A, "ja4": JA4_FOXIO, "version": "TLSv13", "server_name": "example.org"}
    conn = {"uid": "C1", "id.orig_h": "10.0.0.9", "id.orig_p": 50000, "id.resp_h": "10.0.0.10", "id.resp_p": 443,
            "proto": "tcp", "duration": 1.0, "orig_pkts": 4, "resp_pkts": 4, "orig_ip_bytes": 900, "resp_ip_bytes": 3000}
    flows = [f for f in (correlator.add_ssl_record(ssl), correlator.add_conn_record(conn),
                         correlator.add_conn_record(conn), correlator.add_ssl_record(ssl)) if f]
    assert len(flows) == 1
    ev = DetectionPipeline().process_flow(flows[0], track="B_JA3", stream_id="s", sequence=1, mode="LIVE")
    assert ev.flow.forward_endpoint == "10.0.0.9:50000" and ev.tls.sni_value == "example.org"
    assert ev.provenance.sensor.sensor_record_id == "C1"


def test_sensor_attribution_uses_sni_and_responder(engine):
    flow = next(f for f in _zeek_flows() if f["sni"] == "youtube.com")
    from backend.repositories import target_repository
    tgt = target_repository.create({"hostname": "youtube.com", "display_name": "YouTube"})
    ev = DetectionPipeline().process_flow(flow, track="A_FLOW", stream_id="s", sequence=1, mode="LIVE",
                                          target_id=tgt["target_id"])
    assert ev.attribution.status == "ATTRIBUTED" and ev.attribution.target_id == tgt["target_id"]


def test_pipeline_error_event_hides_exception_text(engine, monkeypatch):
    def boom(flow, track="A_FLOW"):
        raise ValueError(r"C:\private\path\secret.parquet")
    monkeypatch.setattr(engine, "predict", boom)
    ev = DetectionPipeline().process_flow(complete_flow_record(), track="A_FLOW", stream_id="s", sequence=1)
    assert ev.detection.status == "ERROR" and ev.detection.prediction == "UNKNOWN"
    assert "private" not in ev.detection.skip_reason and "ValueError" in ev.detection.skip_reason
    assert ev.flow.forward_endpoint == "UNKNOWN" and "0.0.0.0" not in json.dumps(ev.model_dump())


def test_replay_of_a_training_capture_is_flagged_in_sample(engine):
    entry = engine.models["A_FLOW"][0]
    cap = entry["training"]["captures"][0]
    ev = DetectionPipeline().process_flow(complete_flow_record(capture_id=cap, dataset_id="SYN-BEN"),
                                          track="A_FLOW", stream_id="s", sequence=1)
    assert ev.detection.status == "COMPLETED"
    assert "IN_SAMPLE_REPLAY:capture_used_in_training" in ev.detection.ood_flags
    assert any("Out-of-distribution warnings" in e for e in ev.detection.evidence)


def test_websocket_broadcast_delivers_schema_valid_sensor_events(engine):
    class FakeSocket:
        def __init__(self):
            self.sent = []

        async def send_json(self, payload):
            self.sent.append(json.loads(json.dumps(payload, allow_nan=False)))

    manager, sock = ConnectionManager(), FakeSocket()
    manager.active_connections.append(sock)
    flows = _suricata_flows() + _ebpf_flows()
    events = [DetectionPipeline().process_flow(f, track="B_JA3", stream_id="ws", sequence=i, mode="LIVE")
              for i, f in enumerate(flows, start=1)]

    async def send_all():
        for ev in events:
            await manager.broadcast(ev)

    asyncio.run(send_all())
    assert len(sock.sent) == len(events)
    for payload in sock.sent:
        ETTHStreamEvent.model_validate(payload)
        assert payload["event_type"] == "flow.detected" and payload["provenance"]["sensor"] is not None


def test_legacy_replay_events_have_no_sensor_block(engine):
    ev = DetectionPipeline().process_flow(complete_flow_record(dataset_id="DS-011"), track="A_FLOW",
                                          stream_id="s", sequence=1)
    assert ev.provenance.sensor is None and ev.detection.status == "COMPLETED"
