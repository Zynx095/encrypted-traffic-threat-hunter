"""
Local background job manager for research computations.

* Jobs run as separate Python processes (`python -m ml ...` / `python -m pipeline.corpus ...`),
  never inside an HTTP handler or the event loop, so training cannot block live detection
  (separate GIL, below-normal OS priority).
* Only an allow-list of job types with validated parameters can be started; there is no way to
  run an arbitrary command or path.
* At most MAX_CONCURRENT jobs run at once; further jobs wait in QUEUED. An identical job
  (same type and parameters) that is already queued or running is rejected.
* State is persisted to data/research_jobs/jobs.json; logs to data/research_jobs/<job_id>.log.
  Jobs left RUNNING by a previous server process are marked FAILED (interrupted) on start-up.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
JOBS_DIR = BASE_DIR / "data" / "research_jobs"
MAX_CONCURRENT = 1
MIN_FREE_MEMORY_MB = 1500
DATASETS = {"DS-008", "DS-009", "DS-011"}


class JobError(ValueError):
    pass


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def build_command(job_type: str, params: Dict[str, Any]) -> (List[str], Dict[str, Any], Optional[int]):
    """Validate parameters and return (argv, normalised params, expected progress steps)."""
    py = sys.executable
    if job_type == "benchmark_suite":
        from ml.benchmark.suites import SUITES
        name = params.get("suite")
        if name not in SUITES:
            raise JobError(f"Unknown suite '{name}'. Allowed: {sorted(SUITES)}")
        n_boot = int(params.get("n_boot", 1000))
        if not 100 <= n_boot <= 5000:
            raise JobError("n_boot must be between 100 and 5000")
        spec = SUITES[name]
        steps = len(spec["tracks"]) * len(spec["models"]) * len(spec["encodings"])
        return [py, "-m", "ml", "suite", name, "--n-boot", str(n_boot)], {"suite": name, "n_boot": n_boot}, steps
    if job_type == "sequence_suite":
        epochs = int(params.get("epochs", 30))
        if not 1 <= epochs <= 200:
            raise JobError("epochs must be between 1 and 200")
        archs = params.get("archs", ["cnn", "gru"])
        if not archs or any(a not in ("cnn", "gru") for a in archs):
            raise JobError("archs must be a non-empty subset of ['cnn', 'gru']")
        datasets = params.get("datasets")
        argv = [py, "-m", "ml", "sequence", "--epochs", str(epochs), "--archs", ",".join(archs)]
        norm: Dict[str, Any] = {"epochs": epochs, "archs": list(archs)}
        if datasets:
            if any(d not in DATASETS for d in datasets):
                raise JobError(f"datasets must be a subset of {sorted(DATASETS)}")
            argv += ["--datasets", ",".join(datasets)]
            norm["datasets"] = list(datasets)
        return argv, norm, 5
    if job_type == "coverage":
        return [py, "-m", "ml", "coverage"], {}, None
    if job_type == "report":
        return [py, "-m", "ml", "report"], {}, None
    if job_type == "corpus_admission":
        return [py, "-m", "pipeline.corpus", "admit"], {}, None
    if job_type == "replay_set":
        return [py, "-m", "pipeline.corpus", "replay-set"], {}, None
    raise JobError(f"Unknown job type '{job_type}'")


class JobManager:
    def __init__(self, jobs_dir: Path = JOBS_DIR, max_concurrent: int = MAX_CONCURRENT, autostart: bool = True):
        self.dir = Path(jobs_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.dir / "jobs.json"
        self.max_concurrent = max_concurrent
        self._lock = threading.RLock()
        self._procs: Dict[str, subprocess.Popen] = {}
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self._load()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        if autostart:
            self.start()

    # ---------------------------------------------------------------- persistence --
    def _load(self) -> None:
        if self.state_path.exists():
            try:
                self.jobs = {j["job_id"]: j for j in json.loads(self.state_path.read_text(encoding="utf-8"))}
            except Exception as exc:
                logger.error("Unreadable job state %s: %s", self.state_path, exc)
                self.jobs = {}
        for j in self.jobs.values():
            if j["status"] == "RUNNING":
                j.update(status="FAILED", finished_at=_now(), error="INTERRUPTED: server restarted while the job was running")
        self._save()

    def _save(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(list(self.jobs.values()), indent=2, default=str), encoding="utf-8")
        tmp.replace(self.state_path)

    # ------------------------------------------------------------------- public --
    def submit(self, job_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
        argv, norm, steps = build_command(job_type, params or {})
        with self._lock:
            for j in self.jobs.values():
                if j["type"] == job_type and j["params"] == norm and j["status"] in ("QUEUED", "RUNNING"):
                    raise JobError(f"An identical job is already {j['status']}: {j['job_id']}")
            job_id = f"job_{_dt.datetime.now(_dt.timezone.utc).strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex[:6]}"
            job = {"job_id": job_id, "type": job_type, "params": norm, "status": "QUEUED", "created_at": _now(),
                   "started_at": None, "finished_at": None, "progress": None if steps is None else 0.0,
                   "progress_detail": None, "expected_steps": steps, "exit_code": None, "error": None,
                   "artifacts": {}, "resources": {}, "argv": argv[1:]}
            self.jobs[job_id] = job
            self._save()
        return self.public(job)

    def cancel(self, job_id: str) -> Dict[str, Any]:
        with self._lock:
            job = self._get(job_id)
            if job["status"] == "QUEUED":
                job.update(status="CANCELLED", finished_at=_now())
            elif job["status"] == "RUNNING":
                proc = self._procs.get(job_id)
                if proc is not None:
                    self._kill_tree(proc.pid)
                job.update(status="CANCELLED", finished_at=_now(), error="Cancelled by user")
            else:
                raise JobError(f"Job {job_id} is already {job['status']}")
            self._save()
            return self.public(job)

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [self.public(j) for j in sorted(self.jobs.values(), key=lambda j: j["created_at"], reverse=True)]

    def get(self, job_id: str) -> Dict[str, Any]:
        with self._lock:
            return self.public(self._get(job_id))

    def log_tail(self, job_id: str, lines: int = 200) -> Dict[str, Any]:
        self._get(job_id)
        path = self.dir / f"{job_id}.log"
        if not path.exists():
            return {"job_id": job_id, "lines": [], "truncated": False}
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
        lines = max(1, min(lines, 2000))
        return {"job_id": job_id, "lines": content[-lines:], "truncated": len(content) > lines}

    @staticmethod
    def public(job: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in job.items() if k not in ("argv", "expected_steps")}

    # ---------------------------------------------------------------- dispatcher --
    def start(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._loop, name="etth-job-dispatcher", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _get(self, job_id: str) -> Dict[str, Any]:
        if not re.fullmatch(r"job_[0-9TZ]+_[0-9a-f]{6}", job_id or ""):
            raise KeyError(job_id)
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(job_id)
        return job

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:  # the dispatcher must survive individual failures
                logger.exception("Job dispatcher error: %s", exc)
            time.sleep(1.0)

    def tick(self) -> None:
        with self._lock:
            running = [j for j in self.jobs.values() if j["status"] == "RUNNING"]
            for job in running:
                self._poll(job)
            running = [j for j in self.jobs.values() if j["status"] == "RUNNING"]
            if len(running) >= self.max_concurrent:
                return
            queued = sorted((j for j in self.jobs.values() if j["status"] == "QUEUED"), key=lambda j: j["created_at"])
            if not queued:
                return
            self._launch(queued[0])

    def _launch(self, job: Dict[str, Any]) -> None:
        free_mb = psutil.virtual_memory().available / 2**20
        if free_mb < MIN_FREE_MEMORY_MB:
            job.update(status="FAILED", finished_at=_now(),
                       error=f"INSUFFICIENT_RESOURCES: {free_mb:.0f} MB free memory < {MIN_FREE_MEMORY_MB} MB required")
            self._save()
            return
        log = open(self.dir / f"{job['job_id']}.log", "w", encoding="utf-8")
        creation = subprocess.BELOW_NORMAL_PRIORITY_CLASS if os.name == "nt" else 0
        proc = subprocess.Popen([sys.executable] + job["argv"], cwd=str(BASE_DIR), stdout=log, stderr=subprocess.STDOUT,
                                creationflags=creation, env={**os.environ, "PYTHONUNBUFFERED": "1"})
        log.close()   # the child process holds its own handle
        if os.name != "nt":
            try:
                psutil.Process(proc.pid).nice(10)
            except Exception:
                pass
        self._procs[job["job_id"]] = proc
        job.update(status="RUNNING", started_at=_now())
        job["resources"] = {"pid": proc.pid, "peak_rss_mb": 0.0}
        self._save()

    def _poll(self, job: Dict[str, Any]) -> None:
        proc = self._procs.get(job["job_id"])
        if proc is None:
            job.update(status="FAILED", finished_at=_now(), error="Process handle lost")
            self._save()
            return
        try:
            rss = psutil.Process(proc.pid).memory_info().rss / 2**20
            job["resources"]["peak_rss_mb"] = round(max(job["resources"].get("peak_rss_mb", 0.0), rss), 1)
        except psutil.Error:
            pass
        self._update_progress(job)
        code = proc.poll()
        if code is None:
            return
        self._procs.pop(job["job_id"], None)
        job["exit_code"] = code
        job["finished_at"] = _now()
        tail = self.log_tail(job["job_id"], 60)["lines"]
        text = "\n".join(tail)
        m = re.findall(r'"suite_id":\s*"([^"]+)"', text)
        if m:
            job["artifacts"]["suite_id"] = m[-1]
        if job["status"] == "CANCELLED":
            pass
        elif code == 0:
            job["status"] = "COMPLETED"
            if job.get("progress") is not None:
                job["progress"] = 1.0
        else:
            job["status"] = "FAILED"
            job["error"] = f"Process exited with code {code}. Last log lines: " + " | ".join(tail[-5:])
        self._save()

    def _update_progress(self, job: Dict[str, Any]) -> None:
        steps = job.get("expected_steps")
        if not steps:
            return
        path = self.dir / f"{job['job_id']}.log"
        if not path.exists():
            return
        text = path.read_text(encoding="utf-8", errors="replace")
        pattern = "Phase 10 fold" if job["type"] == "sequence_suite" else "Running "
        done = text.count(pattern)
        job["progress"] = round(min(done / steps, 0.99), 4)
        lines = [ln for ln in text.splitlines() if pattern in ln]
        job["progress_detail"] = lines[-1][-160:] if lines else None

    @staticmethod
    def _kill_tree(pid: int) -> None:
        try:
            parent = psutil.Process(pid)
            for child in parent.children(recursive=True):
                child.kill()
            parent.kill()
        except psutil.Error:
            pass


_manager: Optional[JobManager] = None
_manager_lock = threading.Lock()


def get_manager() -> JobManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = JobManager()
        return _manager
