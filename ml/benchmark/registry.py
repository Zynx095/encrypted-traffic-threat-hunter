"""
Immutable experiment registry.

Layout:
    data/experiments/registry/index.jsonl                  append-only event log (one JSON per line)
    data/experiments/phase9/<suite_id>/suite.json           suite configuration + status
    data/experiments/phase9/<suite_id>/<experiment_id>/     record.json, folds.json, predictions.parquet

An experiment directory is created once and never reused. A re-run creates a new experiment id;
earlier results are never overwritten. Failures are recorded with their error message.
Within a suite, a COMPLETED experiment with the same config hash is skipped on resume.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import platform
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline import config as pipeline_config

PROJECT_ROOT = pipeline_config.PROJECT_ROOT
EXPERIMENTS_ROOT = PROJECT_ROOT / "data" / "experiments"
PHASE9_ROOT = EXPERIMENTS_ROOT / "phase9"
PHASE10_ROOT = EXPERIMENTS_ROOT / "phase10"
REGISTRY_INDEX = EXPERIMENTS_ROOT / "registry" / "index.jsonl"

STATUSES = ("RUNNING", "COMPLETED", "FAILED", "INFEASIBLE", "SKIPPED")
STAGES = ("EXPLORATORY", "CONFIRMATORY")


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def config_hash(cfg: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(cfg, sort_keys=True, default=str).encode()).hexdigest()[:16]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def git_revision() -> str:
    try:
        rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=10).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no", "--", ".", ":(exclude)data/verification/mta_stage65"],
                               cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30).stdout.strip()
        return f"{rev}{'+dirty' if dirty else ''}" if rev else "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def environment_snapshot() -> Dict[str, Any]:
    versions = {}
    for mod in ("numpy", "pandas", "sklearn", "scipy", "pyarrow", "torch", "dpkt"):
        try:
            versions[mod] = __import__(mod).__version__
        except Exception:
            versions[mod] = None
    return {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
            "cpu_count": os.cpu_count(), "packages": versions, "source_revision": git_revision()}


def dataset_fingerprint() -> Dict[str, Any]:
    from pipeline.corpus import paths
    out: Dict[str, Any] = {"corpus_manifest": paths.rel(paths.CORPUS_MANIFEST_PATH)}
    if paths.CORPUS_MANIFEST_PATH.exists():
        out["corpus_manifest_sha256"] = sha256_file(paths.CORPUS_MANIFEST_PATH)
        man = json.loads(paths.CORPUS_MANIFEST_PATH.read_text(encoding="utf-8"))
        out["corpus_outputs"] = man.get("outputs", {})
        out["corpus_version"] = man.get("corpus_version")
        out["inputs"] = {k: v.get("sha256") for k, v in man.get("inputs", {}).items()}
    return out


def append_index(event: Dict[str, Any]) -> None:
    REGISTRY_INDEX.parent.mkdir(parents=True, exist_ok=True)
    with open(REGISTRY_INDEX, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, default=str) + "\n")


def _write_json(path: Path, obj: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


class Suite:
    def __init__(self, name: str, cfg: Dict[str, Any], stage: str = "EXPLORATORY", suite_id: Optional[str] = None,
                 root: Optional[Path] = None):
        root = PHASE9_ROOT if root is None else root     # resolved at call time (testable, like the model registry)
        if stage not in STAGES:
            raise ValueError(stage)
        self.name = name
        self.cfg = cfg
        self.stage = stage
        self.suite_id = suite_id or f"{name}-{_dt.datetime.now(_dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        self.dir = Path(root) / self.suite_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "suite.json"
        if self.path.exists():
            self.record = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            self.record = {"suite_id": self.suite_id, "name": name, "stage": stage, "config": cfg,
                           "config_hash": config_hash(cfg), "created_at": now(), "status": "RUNNING",
                           "environment": environment_snapshot(), "dataset": dataset_fingerprint(), "experiments": []}
            _write_json(self.path, self.record)
            append_index({"event": "suite_created", "suite_id": self.suite_id, "name": name, "stage": stage, "at": now()})

    def completed_hashes(self) -> Dict[str, str]:
        out = {}
        for exp_dir in self.dir.iterdir():
            rec = exp_dir / "record.json"
            if exp_dir.is_dir() and rec.exists():
                r = json.loads(rec.read_text(encoding="utf-8"))
                if r.get("status") in ("COMPLETED", "INFEASIBLE"):
                    out[r["config_hash"]] = r["experiment_id"]
        return out

    def finish(self, status: str = "COMPLETED", summary: Optional[Dict[str, Any]] = None) -> None:
        self.record["status"] = status
        self.record["finished_at"] = now()
        if summary is not None:
            self.record["summary"] = summary
        _write_json(self.path, self.record)
        append_index({"event": "suite_finished", "suite_id": self.suite_id, "status": status, "at": now()})


class Experiment:
    def __init__(self, suite: Suite, cfg: Dict[str, Any]):
        self.suite = suite
        self.cfg = cfg
        self.cfg_hash = config_hash(cfg)
        self.experiment_id = f"EXP-{_dt.datetime.now(_dt.timezone.utc).strftime('%Y%m%dT%H%M%S')}-{self.cfg_hash[:8]}-{uuid.uuid4().hex[:4]}"
        self.dir = suite.dir / self.experiment_id
        self.dir.mkdir(parents=True, exist_ok=False)
        self.record = {"experiment_id": self.experiment_id, "suite_id": suite.suite_id, "stage": suite.stage,
                       "config": cfg, "config_hash": self.cfg_hash, "status": "RUNNING", "started_at": now(),
                       "warnings": [], "exclusions": [], "artifacts": {}}
        _write_json(self.dir / "record.json", self.record)
        suite.record["experiments"].append(self.experiment_id)
        _write_json(suite.path, suite.record)
        append_index({"event": "experiment_started", "experiment_id": self.experiment_id, "suite_id": suite.suite_id,
                      "config": cfg, "at": now()})

    def warn(self, msg: str) -> None:
        self.record["warnings"].append(msg)

    def save_artifact(self, name: str, obj: Any) -> str:
        path = self.dir / name
        if name.endswith(".parquet"):
            obj.to_parquet(path, index=False)
        else:
            _write_json(path, obj)
        try:
            rel = path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
        except ValueError:          # suites rooted outside the repository (tests, scratch runs)
            rel = path.resolve().as_posix()
        self.record["artifacts"][name] = {"path": rel, "sha256": sha256_file(path)}
        return rel

    def finish(self, status: str, metrics: Optional[Dict[str, Any]] = None, error: Optional[str] = None,
               extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if status not in STATUSES:
            raise ValueError(status)
        self.record.update({"status": status, "finished_at": now()})
        if metrics is not None:
            self.record["metrics"] = metrics
        if error:
            self.record["error"] = error
        if extra:
            self.record.update(extra)
        _write_json(self.dir / "record.json", self.record)
        append_index({"event": "experiment_finished", "experiment_id": self.experiment_id, "status": status, "at": now()})
        return self.record


def list_suites(roots=None) -> List[Dict[str, Any]]:
    roots = (PHASE9_ROOT, PHASE10_ROOT) if roots is None else roots
    out = []
    for root in roots:
        if root.exists():
            for d in sorted(root.iterdir()):
                p = d / "suite.json"
                if p.exists():
                    rec = json.loads(p.read_text(encoding="utf-8"))
                    rec["phase"] = "PHASE_10" if root == PHASE10_ROOT else "PHASE_9"
                    out.append(rec)
    return out


def suite_dir(suite_id: str) -> Path:
    for root in (PHASE9_ROOT, PHASE10_ROOT):
        if (root / suite_id / "suite.json").exists():
            return root / suite_id
    raise FileNotFoundError(f"Unknown suite {suite_id}")


def load_experiment(suite_id: str, experiment_id: str) -> Dict[str, Any]:
    p = suite_dir(suite_id) / experiment_id / "record.json"
    return json.loads(p.read_text(encoding="utf-8"))
