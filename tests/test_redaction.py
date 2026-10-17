"""Local filesystem paths must not reach API clients (model load errors, job logs)."""
import json

import ml.model_registry as MR
from backend.inference_engine import InferenceEngine
from backend.redaction import _REPO, redact
from backend.research.jobs import JobManager


def test_redact_replaces_repository_home_and_drive_paths():
    text = f"FileNotFoundError: '{_REPO}\\data\\model_registry\\artifacts\\m\\model.json'"
    out = redact(text)
    assert _REPO not in out and out.endswith("model.json'") and "<repo>" in out
    assert redact("score 0.5 at 1.2 ms") == "score 0.5 at 1.2 ms"


def test_registry_entry_with_missing_artifact_reports_load_failed_without_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(MR, "ROOT", tmp_path)
    monkeypatch.setattr(MR, "ARTIFACT_ROOT", tmp_path / "artifacts")
    monkeypatch.setattr(MR, "REGISTRY_PATH", tmp_path / "registry.json")
    (tmp_path / "registry.json").write_text(json.dumps({"models": [{
        "model_id": "missing", "version": 1, "track": "A_FLOW", "estimator": "random_forest", "status": "ACTIVE",
        "artifact": {"format": "etth-tabular-model/1", "path": "artifacts/missing/v1",
                     "sha256": {"model.json": "0" * 64, "arrays.npz": "0" * 64}}}],
        "activation_history": []}), encoding="utf-8")
    eng = InferenceEngine(autoload=True)
    st = eng.load_status["A_FLOW"]
    assert st["status"] == "LOAD_FAILED"
    assert str(tmp_path) not in st["error"] and _REPO not in st["error"]
    res = eng.predict({"flow_id": "x"}, track="A_FLOW")
    assert res["status"] == "SKIPPED" and res["skip_reason"].startswith("NO_VALIDATED_MODEL")


def test_job_log_tail_is_redacted(tmp_path):
    mgr = JobManager(jobs_dir=tmp_path, autostart=False)
    mgr.jobs["job_20261017T000000_abcdef"] = {"job_id": "job_20261017T000000_abcdef", "status": "FAILED", "created_at": "2026-10-17T00:00:00Z"}
    (tmp_path / "job_20261017T000000_abcdef.log").write_text(f'Traceback:\n  File "{_REPO}\\ml\\__main__.py", line 1\nValueError: x\n',
                                       encoding="utf-8")
    lines = mgr.log_tail("job_20261017T000000_abcdef")["lines"]
    assert all(_REPO not in line for line in lines) and any("<repo>" in line for line in lines)
