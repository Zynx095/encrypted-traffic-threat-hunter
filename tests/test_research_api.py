"""Research API and background job manager: status codes, schemas, isolation, allow-listing."""
import sys
import time

import pytest
from fastapi.testclient import TestClient

import backend.research.jobs as J
from backend.main import app
from backend.research.schemas import JobRecord, ResearchDocument

client = TestClient(app)


def test_document_endpoints_use_explicit_status_envelope():
    for url in ("/api/research/corpus/admission", "/api/research/corpus/sufficiency", "/api/research/features/coverage",
                "/api/research/claims", "/api/research/reports/latest", "/api/research/features/governance"):
        r = client.get(url)
        assert r.status_code == 200
        doc = ResearchDocument(**r.json())
        assert doc.status in ("AVAILABLE", "NOT_RUN", "NOT_AVAILABLE")
        if doc.status != "AVAILABLE":
            assert doc.data is None and doc.detail


def test_governance_endpoint_lists_tracks_and_forbidden_columns():
    data = client.get("/api/research/features/governance").json()["data"]
    tracks = {t["track"] for t in data["tracks"]}
    assert {"A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"} <= tracks
    assert any(f["column"] == "dataset_id" for f in data["forbidden"])


def test_identifier_validation_and_not_found():
    assert client.get("/api/research/suites/..%2F..%2Fetc").status_code in (400, 404)
    assert client.get("/api/research/suites/does-not-exist").status_code == 404
    assert client.get("/api/research/experiments/x/y z").status_code == 400
    assert client.get("/api/research/jobs/not-a-job").status_code == 404


def test_model_registry_and_inference_status_shapes():
    r = client.get("/api/research/models")
    assert r.status_code == 200 and set(r.json()) == {"models", "activation_history", "active_by_track"}
    st = client.get("/api/research/inference/status").json()
    assert set(st["tracks"]) == {"A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"}
    assert "latency_ms" in st["metrics"]
    bad = client.post("/api/research/models/nope/versions/1/activate", json={"reason": "testing activation"})
    assert bad.status_code == 400


def test_job_submission_is_allow_listed_and_validated(tmp_path, monkeypatch):
    mgr = J.JobManager(jobs_dir=tmp_path, autostart=False)
    monkeypatch.setattr(J, "_manager", mgr)
    assert client.post("/api/research/jobs", json={"type": "shell", "params": {"cmd": "rm -rf /"}}).status_code == 422
    assert client.post("/api/research/jobs", json={"type": "benchmark_suite", "params": {"suite": "../../x"}}).status_code == 422
    assert client.post("/api/research/jobs", json={"type": "benchmark_suite", "params": {"suite": "pooled_capture_cv", "n_boot": 5}}).status_code == 422
    r = client.post("/api/research/jobs", json={"type": "coverage", "params": {}})
    assert r.status_code == 202 and JobRecord(**r.json()).status == "QUEUED"
    dup = client.post("/api/research/jobs", json={"type": "coverage", "params": {}})
    assert dup.status_code == 409
    job_id = r.json()["job_id"]
    assert client.post(f"/api/research/jobs/{job_id}/cancel").json()["status"] == "CANCELLED"
    assert client.post(f"/api/research/jobs/{job_id}/cancel").status_code == 409


def _fake_command(code: int, sleep: float = 0.0):
    def build(job_type, params):
        prog = f"import time; print('Running fake | step'); time.sleep({sleep}); print('\"suite_id\": \"fake-suite\"'); raise SystemExit({code})"
        return [sys.executable, "-c", prog], dict(params), 1
    return build


def _wait(mgr, job_id, states, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        mgr.tick()
        if mgr.get(job_id)["status"] in states:
            return mgr.get(job_id)
        time.sleep(0.2)
    raise AssertionError(mgr.get(job_id))


def test_jobs_run_out_of_process_and_record_outcomes(tmp_path, monkeypatch):
    mgr = J.JobManager(jobs_dir=tmp_path, autostart=False)
    monkeypatch.setattr(J, "build_command", _fake_command(0))
    ok = mgr.submit("coverage", {"n": 1})
    done = _wait(mgr, ok["job_id"], {"COMPLETED", "FAILED"})
    assert done["status"] == "COMPLETED" and done["exit_code"] == 0 and done["artifacts"]["suite_id"] == "fake-suite"
    assert done["resources"]["pid"] != __import__("os").getpid()
    assert any("Running fake" in ln for ln in mgr.log_tail(ok["job_id"])["lines"])
    monkeypatch.setattr(J, "build_command", _fake_command(3))
    bad = mgr.submit("coverage", {"n": 2})
    failed = _wait(mgr, bad["job_id"], {"COMPLETED", "FAILED"})
    assert failed["status"] == "FAILED" and failed["exit_code"] == 3 and "code 3" in failed["error"]


def test_concurrency_limit_and_cancellation_of_running_job(tmp_path, monkeypatch):
    mgr = J.JobManager(jobs_dir=tmp_path, autostart=False, max_concurrent=1)
    monkeypatch.setattr(J, "build_command", _fake_command(0, sleep=20))
    a = mgr.submit("coverage", {"n": "a"})
    b = mgr.submit("coverage", {"n": "b"})
    _wait(mgr, a["job_id"], {"RUNNING"})
    mgr.tick()
    assert mgr.get(b["job_id"])["status"] == "QUEUED"
    assert mgr.cancel(a["job_id"])["status"] == "CANCELLED"
    _wait(mgr, b["job_id"], {"RUNNING"})
    mgr.cancel(b["job_id"])


def test_interrupted_jobs_are_marked_failed_on_restart(tmp_path, monkeypatch):
    mgr = J.JobManager(jobs_dir=tmp_path, autostart=False)
    monkeypatch.setattr(J, "build_command", _fake_command(0, sleep=20))
    job = mgr.submit("coverage", {"n": "r"})
    _wait(mgr, job["job_id"], {"RUNNING"})
    pid = mgr.get(job["job_id"])["resources"]["pid"]
    restarted = J.JobManager(jobs_dir=tmp_path, autostart=False)
    rec = restarted.get(job["job_id"])
    assert rec["status"] == "FAILED" and rec["error"].startswith("INTERRUPTED")
    J.JobManager._kill_tree(pid)
