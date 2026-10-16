"""Phase 9.10: safe artefacts, model registry (activation / rollback) and registry-backed inference."""
import json

import numpy as np
import pandas as pd
import pytest

import ml.model_registry as MR
from backend.inference_engine import InferenceEngine
from backend.schemas import DetectionDetails, ETTHStreamEvent
from ml.estimators.artifact import ArtifactError, SafeTabularModel, export_model
from ml.estimators.preprocessing import TabularPreprocessor
from ml.estimators.zoo import MODEL_SPECS
from tests.ml_fixtures import complete_flow_record, fixture_models, synthetic_corpus


@pytest.fixture()
def tmp_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(MR, "ROOT", tmp_path)
    monkeypatch.setattr(MR, "ARTIFACT_ROOT", tmp_path / "artifacts")
    monkeypatch.setattr(MR, "REGISTRY_PATH", tmp_path / "registry.json")
    return tmp_path


# ------------------------------------------------------------------ artefacts --
@pytest.mark.parametrize("model", ["logreg", "random_forest", "extra_trees"])
def test_safe_artifact_reproduces_sklearn_scores(tmp_path, model):
    df = synthetic_corpus(seed=3)
    X = df[["flow_duration", "iat_std", "ja3_hash"]]
    spec = MODEL_SPECS[model]
    pre = TabularPreprocessor(numeric=["flow_duration", "iat_std"], categorical=["ja3_hash"], scale=spec.scale).fit(X.iloc[:300])
    clf = spec.build(seed=0).fit(pre.transform(X.iloc[:300]), df["y"].iloc[:300])
    hashes = export_model(pre, clf, tmp_path / "m", {"t": 1})
    loaded = SafeTabularModel.load(tmp_path / "m", hashes)
    ref = clf.predict_proba(pre.transform(X.iloc[300:]))[:, 1]
    assert np.allclose(loaded.predict_proba1(X.iloc[300:]), ref, atol=1e-12)


def test_artifact_checksum_and_format_enforced(tmp_path):
    df = synthetic_corpus()
    pre = TabularPreprocessor(numeric=["flow_duration"]).fit(df)
    clf = MODEL_SPECS["logreg"].build(seed=0).fit(pre.transform(df), df["y"])
    hashes = export_model(pre, clf, tmp_path / "m", {})
    (tmp_path / "m" / "model.json").write_text((tmp_path / "m" / "model.json").read_text().replace('"t": 1', '"t": 2') + " ")
    with pytest.raises(ArtifactError, match="Checksum"):
        SafeTabularModel.load(tmp_path / "m", hashes)
    with pytest.raises(ArtifactError):
        export_model(pre, MODEL_SPECS["hist_gb"].build(seed=0).fit(pre.transform(df), df["y"]), tmp_path / "h", {})


# ------------------------------------------------------------------- registry --
def test_train_activate_and_rollback(tmp_registry, monkeypatch):
    import ml.benchmark.registry as R
    monkeypatch.setattr(R, "dataset_fingerprint", lambda: {"corpus_version": "test-fixture"})
    df = synthetic_corpus(captures_per_class=6, flows_per_capture=30)
    e1 = MR.train_deployable("E_JA4_FLOW", "random_forest", df, ["EXP-fixture"], {"min_samples_leaf": 1})
    e2 = MR.train_deployable("E_JA4_FLOW", "random_forest", df, ["EXP-fixture"], {"min_samples_leaf": 5})
    assert (e1["version"], e2["version"]) == (1, 2) and e1["status"] == e2["status"] == "CANDIDATE"
    assert e1["calibration"]["status"] in ("PLATT_ON_INNER_CAPTURE_OOF", "UNCALIBRATED")
    assert set(e1["feature_schema"]["categorical"]) >= {"ja4"}
    MR.activate(e1["model_id"], 1, "first activation")
    MR.activate(e2["model_id"], 2, "newer candidate")
    assert MR.active_models()["E_JA4_FLOW"]["version"] == 2
    MR.rollback("E_JA4_FLOW")
    assert MR.active_models()["E_JA4_FLOW"]["version"] == 1
    reg = MR.load_registry()
    assert len([m for m in reg["models"] if m["status"] == "ACTIVE"]) == 1
    assert reg["activation_history"][-1]["reason"].startswith("rollback")


def test_registry_refuses_paths_outside_artifact_root_and_tampered_artifacts(tmp_registry, monkeypatch):
    import ml.benchmark.registry as R
    monkeypatch.setattr(R, "dataset_fingerprint", lambda: {})
    df = synthetic_corpus()
    e = MR.train_deployable("C_JA4", "logreg", df, [], None)
    bad = dict(e, artifact=dict(e["artifact"], path="../../etc"))
    with pytest.raises(MR.ModelRegistryError):
        MR.load_model(bad)
    (tmp_registry / e["artifact"]["path"] / "arrays.npz").write_bytes(b"tampered")
    with pytest.raises(ArtifactError):
        MR.activate(e["model_id"], e["version"], "should fail verification")
    with pytest.raises(MR.ModelRegistryError):
        MR.train_deployable("A_FLOW", "hist_gb", df, [], None)


# ------------------------------------------------------------------ inference --
@pytest.fixture()
def engine(tmp_path):
    eng = InferenceEngine(autoload=False)
    for track, (entry, model) in fixture_models(tmp_path).items():
        eng.install(track, entry, model)
    return eng


def test_no_model_means_skipped_never_label_echo():
    eng = InferenceEngine(autoload=False)
    for label in ("MALICIOUS", "BENIGN"):
        res = eng.predict(complete_flow_record(label=label), track="A_FLOW")
        assert res["status"] == "SKIPPED" and res["prediction"] == "UNKNOWN"
        assert res["skip_reason"].startswith("NO_VALIDATED_MODEL")
        assert res["model_name"] != "ETTH-GroundTruthRule"


def test_complete_record_is_scored_with_provenance(engine):
    res = engine.predict(complete_flow_record(), track="E_JA4_FLOW")
    assert res["status"] == "COMPLETED" and res["prediction"] in ("MALICIOUS", "BENIGN")
    assert res["model_id"] == "fixture-e_ja4_flow" and res["decision_threshold"] == 0.5
    assert 0.0 <= res["threat_score"] <= 1.0
    DetectionDetails(**{k: v for k, v in res.items() if k in DetectionDetails.model_fields})


def test_label_field_never_influences_score(engine):
    a = engine.predict(complete_flow_record(label="MALICIOUS"), track="A_FLOW")
    b = engine.predict(complete_flow_record(label="BENIGN"), track="A_FLOW")
    assert a["threat_score"] == b["threat_score"]


def test_incompatible_schema_rejected_without_invention(engine):
    sparse = {"flow_id": "s", "flow_duration": 10.0, "total_packets": 50, "total_bytes": 10000}
    res = engine.predict(sparse, track="A_FLOW")
    assert res["status"] == "SKIPPED" and res["skip_reason"].startswith("INCOMPATIBLE_FEATURE_SCHEMA")
    rec = complete_flow_record(flow_duration=None)       # never missing in training
    assert engine.predict(rec, track="A_FLOW")["skip_reason"].startswith("INCOMPATIBLE_FEATURE_SCHEMA")
    rec = complete_flow_record(iat_std=float("nan"))      # legitimately undefined, seen in training
    assert engine.predict(rec, track="A_FLOW")["status"] == "COMPLETED"
    rec = complete_flow_record(live_feature_window_truncated=True)
    assert engine.predict(rec, track="A_FLOW")["status"] == "SKIPPED"


def test_missing_fingerprint_and_unsupported_track_messages_preserved(engine):
    assert "JA3 fingerprint missing" in engine.predict(complete_flow_record(ja3_hash=None), "D_JA3_FLOW")["skip_reason"]
    assert "JA4 fingerprint missing" in engine.predict(complete_flow_record(ja4=None), "C_JA4")["skip_reason"]
    assert "Unsupported model track" in engine.predict(complete_flow_record(), "Z_TRACK")["skip_reason"]


def test_ood_flags_and_latency_metrics(engine):
    res = engine.predict(complete_flow_record(flow_duration=1e6, ja3_hash="never-seen"), track="D_JA3_FLOW")
    assert "OUT_OF_TRAINING_RANGE:flow_duration" in res["ood_flags"]
    assert "UNSEEN_CATEGORY:ja3_hash" in res["ood_flags"]
    snap = engine.metrics.snapshot()
    assert snap["by_status"].get("COMPLETED", 0) >= 1 and snap["latency_ms"]["n"] >= 1


def test_canonical_event_still_validates_with_and_without_new_fields(engine):
    from backend.detection_pipeline import DetectionPipeline
    import backend.detection_pipeline as dp
    old = dp.inference_engine
    dp.inference_engine = engine
    try:
        ev = DetectionPipeline().process_flow(complete_flow_record(dataset_id="DS-011"), track="C_JA4", stream_id="s", sequence=1)
    finally:
        dp.inference_engine = old
    payload = ev.model_dump()
    assert payload["detection"]["model_id"] == "fixture-c_ja4"
    legacy = {k: v for k, v in payload["detection"].items() if k not in ("model_id", "model_version", "research_status",
                                                                          "calibration_status", "decision_threshold", "ood_flags")}
    ETTHStreamEvent.model_validate({**payload, "detection": legacy})
    assert ev.flow.forward_endpoint == "UNKNOWN"          # no invented endpoints
