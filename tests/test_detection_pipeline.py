import pytest
import asyncio
from backend.inference_engine import inference_engine
from backend.detection_pipeline import detection_pipeline
from backend.schemas import ETTHStreamEvent

def test_1_flow_only_inference():
    flow = {
        "flow_id": "test_f1",
        "flow_duration": 10.0,
        "total_packets": 50,
        "total_bytes": 10000,
        "label": "BENIGN"
    }
    res = inference_engine.predict(flow, track="A_FLOW")
    assert res["status"] == "COMPLETED"
    assert res["track"] == "A_FLOW"
    assert 0.0 <= res["threat_score"] <= 1.0
    assert len(res["evidence"]) > 0

def test_2_ja3_only_inference():
    flow = {
        "flow_id": "test_f2",
        "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
        "label": "MALICIOUS"
    }
    res = inference_engine.predict(flow, track="B_JA3")
    assert res["status"] == "COMPLETED"
    assert res["track"] == "B_JA3"

def test_3_ja4_only_inference():
    flow = {
        "flow_id": "test_f3",
        "ja4": "t13d151600_8daaf6152771_e8006e86689d",
        "label": "MALICIOUS"
    }
    res = inference_engine.predict(flow, track="C_JA4")
    assert res["status"] == "COMPLETED"
    assert res["track"] == "C_JA4"

def test_4_ja3_flow_inference():
    flow = {
        "flow_id": "test_f4",
        "flow_duration": 15.0,
        "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
        "label": "MALICIOUS"
    }
    res = inference_engine.predict(flow, track="D_JA3_FLOW")
    assert res["status"] == "COMPLETED"
    assert res["track"] == "D_JA3_FLOW"

def test_5_ja4_flow_inference():
    flow = {
        "flow_id": "test_f5",
        "flow_duration": 15.0,
        "ja4": "t13d151600_8daaf6152771_e8006e86689d",
        "label": "MALICIOUS"
    }
    res = inference_engine.predict(flow, track="E_JA4_FLOW")
    assert res["status"] == "COMPLETED"
    assert res["track"] == "E_JA4_FLOW"

def test_6_missing_ja3_handling():
    flow = {
        "flow_id": "test_f6",
        "ja3_hash": None,
        "label": "MALICIOUS"
    }
    res = inference_engine.predict(flow, track="D_JA3_FLOW")
    assert res["status"] == "SKIPPED"
    assert "JA3 fingerprint missing" in res["skip_reason"]
    assert res["prediction"] == "UNKNOWN"

def test_7_missing_ja4_handling():
    flow = {
        "flow_id": "test_f7",
        "ja4": None,
        "label": "MALICIOUS"
    }
    res = inference_engine.predict(flow, track="E_JA4_FLOW")
    assert res["status"] == "SKIPPED"
    assert "JA4 fingerprint missing" in res["skip_reason"]
    assert res["prediction"] == "UNKNOWN"

def test_8_unsupported_model_track():
    flow = {"flow_id": "test_f8"}
    res = inference_engine.predict(flow, track="INVALID_TRACK")
    assert res["status"] == "SKIPPED"
    assert "Unsupported model track" in res["skip_reason"]

def test_9_structured_detection_evidence():
    flow = {
        "flow_id": "test_f9",
        "flow_duration": 5.0,
        "total_packets": 20,
        "total_bytes": 4000,
        "ja3_hash": "e7d705a3286e19ea42f587b344ee6865"
    }
    res = inference_engine.predict(flow, track="D_JA3_FLOW")
    assert isinstance(res["evidence"], list)
    assert len(res["evidence"]) > 0

def test_10_threat_score_range():
    flow = {"flow_id": "test_f10", "flow_duration": 1.0}
    for tr in ["A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"]:
        res = inference_engine.predict(flow, track=tr)
        assert 0.0 <= res["threat_score"] <= 1.0

def test_11_pipeline_generated_canonical_event():
    flow = {
        "flow_id": "test_f11",
        "flow_duration": 20.0,
        "dataset_id": "DS-008",
        "label": "MALICIOUS"
    }
    event = detection_pipeline.process_flow(flow, track="A_FLOW", stream_id="s1", sequence=1)
    assert isinstance(event, ETTHStreamEvent)
    assert event.event_id == "evt_s1_00001"
    assert event.flow.flow_id == "test_f11"
    assert event.detection.track == "A_FLOW"

def test_12_provenance_model_feature_separation():
    flow = {
        "flow_id": "test_f12",
        "dataset_id": "DS-008",
        "source_file": "Zeus.pcap",
        "label": "MALICIOUS"
    }
    event = detection_pipeline.process_flow(flow, track="A_FLOW", stream_id="s1", sequence=2)
    # Provenance details stored in provenance object, not in model feature matrix
    assert event.provenance.dataset_id == "DS-008"
    assert event.provenance.source_file == "Zeus.pcap"
    assert "dataset_id" not in inference_engine.flow_stat_cols
    assert "source_file" not in inference_engine.flow_stat_cols


def test_13_per_flow_failure_isolation():
    # Bad flow with incompatible data types
    bad_flow = {"flow_id": object()}
    event = detection_pipeline.process_flow(bad_flow, track="A_FLOW", stream_id="s1", sequence=3)
    assert isinstance(event, ETTHStreamEvent)
    assert event.detection.status == "ERROR" or event.event_type == "flow.detected"
