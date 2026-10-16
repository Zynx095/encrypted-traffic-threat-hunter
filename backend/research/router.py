"""
/api/research — read-only access to persisted research artefacts plus controlled actions
(job submission/cancellation, model activation/rollback).

Every document endpoint returns a ResearchDocument envelope whose status distinguishes
AVAILABLE (served from disk), NOT_RUN (the producing step has never run) and NOT_AVAILABLE
(the artefact is missing or unreadable). Identifiers are validated against a strict pattern
and resolved under fixed roots; no client-supplied path is ever opened.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from backend.research.jobs import JobError, get_manager
from backend.research.schemas import (ActivateRequest, DatasetSummary, JobCreateRequest, JobLog, JobRecord,
                                      ModelRegistryView, ModelVersion, ResearchDocument, SuiteSummary)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/research", tags=["research"])

BASE_DIR = Path(__file__).resolve().parent.parent.parent
CORPUS_DIR = BASE_DIR / "data" / "corpus"
DIAG_DIR = BASE_DIR / "data" / "experiments" / "phase9" / "diagnostics"
REPORT_DIR = BASE_DIR / "data" / "experiments" / "reports"
CORPUS_MANIFEST = BASE_DIR / "data" / "processed" / "v3" / "corpus_manifest.json"
SAFE_ID = re.compile(r"^[A-Za-z0-9_.:\-]{1,120}$")


def _doc(path: Path, not_run_detail: str) -> ResearchDocument:
    rel = path.relative_to(BASE_DIR).as_posix()
    if not path.exists():
        return ResearchDocument(status="NOT_RUN", source=rel, detail=not_run_detail)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.exception("Unreadable research artefact %s", rel)
        return ResearchDocument(status="NOT_AVAILABLE", source=rel, detail="Artefact exists but could not be parsed.")
    gen = data.get("generated_at") if isinstance(data, dict) else None
    return ResearchDocument(status="AVAILABLE", source=rel, generated_at=gen, data=data if isinstance(data, dict) else {"items": data})


def _check_id(value: str) -> str:
    if not SAFE_ID.fullmatch(value or ""):
        raise HTTPException(status_code=400, detail="Invalid identifier")
    return value


# ------------------------------------------------------------------- datasets --
@router.get("/datasets", response_model=List[DatasetSummary])
def list_datasets():
    path = CORPUS_DIR / "dataset_registry.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="NOT_RUN: dataset registry has not been created (python -m pipeline.corpus seed)")
    reg = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for d in reg.get("datasets", []):
        out.append(DatasetSummary(dataset_id=d["dataset_id"], name=d.get("name", ""), state=d.get("state", "UNKNOWN"),
                                  access_category=str(d.get("access_category", "UNKNOWN")), license=d.get("license"),
                                  composition=d.get("composition"), flow_count=d.get("flow_count"),
                                  research_role=d.get("research_role"), exclusion_reasons=d.get("exclusion_reasons") or [],
                                  last_transition=(d.get("history") or [None])[-1]))
    return out


@router.get("/datasets/{dataset_id}")
def get_dataset(dataset_id: str) -> Dict[str, Any]:
    _check_id(dataset_id)
    path = CORPUS_DIR / "dataset_registry.json"
    if path.exists():
        for d in json.loads(path.read_text(encoding="utf-8")).get("datasets", []):
            if d["dataset_id"] == dataset_id:
                return d
    raise HTTPException(status_code=404, detail="Dataset not found")


@router.get("/corpus/admission", response_model=ResearchDocument)
def corpus_admission():
    return _doc(CORPUS_DIR / "admission_report.json", "Run python -m pipeline.corpus admit")


@router.get("/corpus/sufficiency", response_model=ResearchDocument)
def corpus_sufficiency():
    return _doc(CORPUS_DIR / "sufficiency_assessment.json", "Run python -m pipeline.corpus admit")


@router.get("/corpus/manifest", response_model=ResearchDocument)
def corpus_manifest():
    return _doc(CORPUS_MANIFEST, "Corpus v3 has not been built on this machine (python -m pipeline.corpus build)")


@router.get("/corpus/capture-plan", response_model=ResearchDocument)
def capture_plan():
    return _doc(CORPUS_DIR / "capture_plan.json", "Run python -m pipeline.corpus plan")


# ------------------------------------------------------------------- features --
@router.get("/features/governance", response_model=ResearchDocument)
def feature_governance():
    from ml.features.governance import CANONICAL_TRACKS, FORBIDDEN, SCHEMA_VERSION, TRACKS, registry_table, schema_fingerprint
    return ResearchDocument(status="AVAILABLE", source="ml/features/governance.py", data={
        "schema_version": SCHEMA_VERSION,
        "tracks": [dict(TRACKS[t].to_dict(), schema_fingerprint=schema_fingerprint(t)) for t in TRACKS],
        "canonical_tracks": list(CANONICAL_TRACKS),
        "features": registry_table(),
        "forbidden": [{"column": k, "reason": v} for k, v in sorted(FORBIDDEN.items())],
    })


@router.get("/features/coverage", response_model=ResearchDocument)
def feature_coverage():
    return _doc(DIAG_DIR / "coverage_report.json", "Run python -m ml coverage")


@router.get("/features/shift", response_model=ResearchDocument)
def feature_shift():
    return _doc(DIAG_DIR / "shift_report.json", "Run python -m ml coverage")


# --------------------------------------------------------------- experiments --
def _suite_summaries() -> List[SuiteSummary]:
    from ml.benchmark.registry import list_suites
    out = []
    for s in list_suites():
        statuses = (s.get("summary") or {}).get("statuses") or {}
        out.append(SuiteSummary(suite_id=s["suite_id"], name=s["name"], phase=s.get("phase", "PHASE_9"), stage=s.get("stage", "EXPLORATORY"),
                                status=s.get("status", "UNKNOWN"), created_at=s.get("created_at"), finished_at=s.get("finished_at"),
                                experiments=len(s.get("experiments", [])), statuses={str(k): int(v) for k, v in statuses.items()},
                                evaluation_population=s.get("evaluation_population")))
    return out


@router.get("/suites", response_model=List[SuiteSummary])
def list_suites():
    return _suite_summaries()


@router.get("/suites/{suite_id}")
def get_suite(suite_id: str) -> Dict[str, Any]:
    from ml.benchmark.registry import suite_dir
    _check_id(suite_id)
    try:
        d = suite_dir(suite_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Suite not found")
    out = {"suite": json.loads((d / "suite.json").read_text(encoding="utf-8"))}
    summ = d / "summary.json"
    out["summary"] = json.loads(summ.read_text(encoding="utf-8")) if summ.exists() else None
    out["explanations"] = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("explain_*.json"))}
    return out


@router.get("/experiments/{suite_id}/{experiment_id}")
def get_experiment(suite_id: str, experiment_id: str) -> Dict[str, Any]:
    from ml.benchmark.registry import suite_dir
    _check_id(suite_id); _check_id(experiment_id)
    try:
        d = suite_dir(suite_id) / experiment_id
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Suite not found")
    if not (d / "record.json").exists():
        raise HTTPException(status_code=404, detail="Experiment not found")
    rec = json.loads((d / "record.json").read_text(encoding="utf-8"))
    rec.pop("traceback", None)   # never expose stack traces to clients
    folds = d / "folds.json"
    rec["folds"] = json.loads(folds.read_text(encoding="utf-8")) if folds.exists() else None
    return rec


@router.get("/benchmarks/latest")
def latest_benchmarks() -> Dict[str, Any]:
    """Most recent finished suite per suite name, with its summary rows."""
    from ml.benchmark.registry import suite_dir
    latest: Dict[str, SuiteSummary] = {}
    for s in _suite_summaries():
        if s.status.startswith("COMPLETED") and (s.name not in latest or (s.created_at or "") > (latest[s.name].created_at or "")):
            latest[s.name] = s
    out = {}
    for name, s in sorted(latest.items()):
        summ = suite_dir(s.suite_id) / "summary.json"
        out[name] = {"suite": s.model_dump(), "summary": json.loads(summ.read_text(encoding="utf-8")) if summ.exists() else None}
    from ml.benchmark.suites import CONFIRMATORY_POLICY, SUITES
    not_run = sorted(set(SUITES) - set(out))
    return {"suites": out, "not_run": not_run, "confirmatory_policy": CONFIRMATORY_POLICY}


# --------------------------------------------------------------------- models --
@router.get("/models", response_model=ModelRegistryView)
def model_registry():
    from ml.model_registry import active_models, load_registry
    reg = load_registry()
    models = [ModelVersion(**{k: m.get(k) for k in ModelVersion.model_fields if m.get(k) is not None}) for m in reg["models"]]
    return ModelRegistryView(models=models, activation_history=reg.get("activation_history", []),
                             active_by_track={t: f"{m['model_id']}:v{m['version']}" for t, m in active_models(reg).items()})


@router.post("/models/{model_id}/versions/{version}/activate", response_model=ModelVersion)
def activate_model(model_id: str, version: int, payload: ActivateRequest):
    from backend.inference_engine import inference_engine
    from ml.model_registry import ModelRegistryError, activate
    _check_id(model_id)
    try:
        entry = activate(model_id, version, payload.reason)
    except ModelRegistryError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        logger.exception("Activation failed")
        raise HTTPException(status_code=500, detail="Activation failed: artefact verification error (see server log)")
    inference_engine.reload()
    return ModelVersion(**{k: entry.get(k) for k in ModelVersion.model_fields if entry.get(k) is not None})


@router.post("/models/rollback/{track}", response_model=ModelVersion)
def rollback_model(track: str):
    from backend.inference_engine import inference_engine
    from ml.model_registry import ModelRegistryError, rollback
    _check_id(track)
    try:
        entry = rollback(track)
    except ModelRegistryError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    inference_engine.reload()
    return ModelVersion(**{k: entry.get(k) for k in ModelVersion.model_fields if entry.get(k) is not None})


@router.get("/inference/status")
def inference_status() -> Dict[str, Any]:
    from backend.inference_engine import inference_engine
    return inference_engine.status()


@router.post("/inference/reload")
def inference_reload() -> Dict[str, Any]:
    from backend.inference_engine import inference_engine
    return {"tracks": inference_engine.reload()}


# ----------------------------------------------------------------------- jobs --
@router.get("/jobs", response_model=List[JobRecord])
def list_jobs():
    return get_manager().list()


@router.post("/jobs", response_model=JobRecord, status_code=202)
def submit_job(payload: JobCreateRequest):
    try:
        return get_manager().submit(payload.type, payload.params)
    except JobError as exc:
        status = 409 if "identical job" in str(exc) else 422
        raise HTTPException(status_code=status, detail=str(exc))


@router.get("/jobs/{job_id}", response_model=JobRecord)
def get_job(job_id: str):
    try:
        return get_manager().get(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")


@router.get("/jobs/{job_id}/logs", response_model=JobLog)
def job_logs(job_id: str, tail: int = Query(200, ge=1, le=2000)):
    try:
        return get_manager().log_tail(job_id, tail)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")


@router.post("/jobs/{job_id}/cancel", response_model=JobRecord)
def cancel_job(job_id: str):
    try:
        return get_manager().cancel(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")
    except JobError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


# ------------------------------------------------------------ claims & reports --
@router.get("/claims", response_model=ResearchDocument)
def claims():
    return _doc(REPORT_DIR / "claim_ledger.json", "Run python -m ml report")


@router.get("/reports/latest", response_model=ResearchDocument)
def latest_report():
    return _doc(REPORT_DIR / "latest_report.json", "Run python -m ml report")


@router.get("/reports/latest/markdown", response_class=PlainTextResponse)
def latest_report_markdown():
    path = REPORT_DIR / "latest_report.md"
    if not path.exists():
        raise HTTPException(status_code=404, detail="NOT_RUN: run python -m ml report")
    return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")
