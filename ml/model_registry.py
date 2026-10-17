"""
Model registry for real-time inference.

    data/model_registry/registry.json                       versioned metadata (small, reviewable)
    data/model_registry/artifacts/<model_id>/v<N>/          safe artefacts (git-ignored, regenerable)

Each registered version records its track, input schema, training corpus fingerprint,
evaluation experiments, calibration status, thresholds chosen on validation data, OOD reference
statistics, known limitations and artefact checksums. Exactly one version per track can be
ACTIVE. Activation history is kept so a previous version can be restored (rollback).
Artefacts are loaded only from the artefact root, only through registry entries, and only
after their SHA-256 checksums match.
"""
from __future__ import annotations

import datetime as _dt
import json
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from ml.estimators.artifact import SafeTabularModel, export_model
from ml.estimators.preprocessing import TabularPreprocessor
from ml.estimators.zoo import MODEL_SPECS
from ml.evaluation import metrics as M
from ml.evaluation.splits import InfeasibleSplit, make_folds
from ml.features.governance import SCHEMA_VERSION, TRACKS, population_mask, schema_fingerprint, track_columns
from pipeline import config as pipeline_config

ROOT = pipeline_config.PROJECT_ROOT / "data" / "model_registry"
REGISTRY_PATH = ROOT / "registry.json"
ARTIFACT_ROOT = ROOT / "artifacts"
STATUSES = ("CANDIDATE", "ACTIVE", "INACTIVE", "RETIRED")
RESEARCH_STATUS = "RESEARCH_PILOT_SOURCE_CONFOUNDED"
DEFAULT_LIMITATIONS = [
    "Trained on exploratory, source-confounded data: each dataset contributes a single class.",
    "Labels are capture-level; benign background traffic inside malware captures is labelled malicious.",
    "Benign training traffic is 2017 browser traffic; modern benign clients are out of distribution.",
    "Scores are not evidence of maliciousness in live traffic; they indicate similarity to the training captures.",
]

_lock = threading.Lock()


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


class ModelRegistryError(ValueError):
    pass


def load_registry(path: Optional[Path] = None) -> Dict[str, Any]:
    path = Path(path or REGISTRY_PATH)   # resolved at call time (monkeypatch-safe)
    if not path.exists():
        return {"schema_version": "1.0", "models": [], "activation_history": []}
    return json.loads(path.read_text(encoding="utf-8"))


def save_registry(reg: Dict[str, Any], path: Optional[Path] = None) -> None:
    path = Path(path or REGISTRY_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    reg["updated_at"] = _now()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(reg, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def find(reg: Dict[str, Any], model_id: str, version: Optional[int] = None) -> Optional[Dict[str, Any]]:
    cands = [m for m in reg["models"] if m["model_id"] == model_id and (version is None or m["version"] == version)]
    return sorted(cands, key=lambda m: m["version"])[-1] if cands else None


def active_models(reg: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    reg = reg or load_registry()
    return {m["track"]: m for m in reg["models"] if m["status"] == "ACTIVE"}


def activate(model_id: str, version: int, reason: str, path: Optional[Path] = None) -> Dict[str, Any]:
    with _lock:
        reg = load_registry(path)
        entry = find(reg, model_id, version)
        if entry is None:
            raise ModelRegistryError(f"Unknown model {model_id} v{version}")
        if entry["status"] == "RETIRED":
            raise ModelRegistryError("Retired models cannot be activated")
        verify_artifact(entry)
        previous = active_models(reg).get(entry["track"])
        for m in reg["models"]:
            if m["track"] == entry["track"] and m["status"] == "ACTIVE":
                m["status"] = "INACTIVE"
        entry["status"] = "ACTIVE"
        reg["activation_history"].append({"at": _now(), "track": entry["track"], "activated": f"{model_id}:v{version}",
                                          "previous": f"{previous['model_id']}:v{previous['version']}" if previous else None,
                                          "reason": reason})
        save_registry(reg, path)
        return entry


def rollback(track: str, path: Optional[Path] = None) -> Dict[str, Any]:
    """Re-activate the version that was active before the current one for `track`."""
    reg = load_registry(path)
    hist = [h for h in reg["activation_history"] if h["track"] == track]
    if not hist or not hist[-1].get("previous"):
        raise ModelRegistryError(f"No previous version to roll back to for {track}")
    mid, ver = hist[-1]["previous"].rsplit(":v", 1)
    return activate(mid, int(ver), reason=f"rollback of {hist[-1]['activated']}", path=path)


def _artifact_dir(entry: Dict[str, Any]) -> Path:
    d = (ROOT / entry["artifact"]["path"]).resolve()
    if ARTIFACT_ROOT.resolve() not in d.parents:
        raise ModelRegistryError(f"Artefact path outside the controlled artefact root: {entry['artifact']['path']}")
    return d


def verify_artifact(entry: Dict[str, Any]) -> None:
    SafeTabularModel.load(_artifact_dir(entry), entry["artifact"]["sha256"])


def load_model(entry: Dict[str, Any]) -> SafeTabularModel:
    return SafeTabularModel.load(_artifact_dir(entry), entry["artifact"]["sha256"])


def _ood_reference(X: pd.DataFrame, cols: Dict[str, List[str]]) -> Dict[str, Any]:
    ref: Dict[str, Any] = {"numeric_quantiles": {}, "categorical_vocab_size": {}}
    for c in cols["numeric"]:
        v = pd.to_numeric(X[c], errors="coerce").dropna()
        if len(v):
            ref["numeric_quantiles"][c] = {"q005": float(v.quantile(0.005)), "q995": float(v.quantile(0.995))}
    return ref


def train_deployable(track: str, model: str, df_all: pd.DataFrame, evaluation_experiments: List[str],
                     selected_params: Optional[Dict[str, Any]] = None, seed: int = 42,
                     limitations: Optional[List[str]] = None, path: Optional[Path] = None) -> Dict[str, Any]:
    """Fit a deployable model on the full track population and register it as a CANDIDATE version."""
    from ml.benchmark.registry import dataset_fingerprint
    from ml.benchmark.runner import _fit_score, _matrix
    spec = MODEL_SPECS[model]
    if not spec.exportable:
        raise ModelRegistryError(f"{model} is not exportable to the safe artefact format")
    cols = track_columns(track)
    df = df_all.loc[population_mask(df_all, track)].reset_index(drop=True)
    if df["y"].nunique() < 2:
        raise ModelRegistryError("Track population has a single class")
    X, y = _matrix(df, cols), df["y"].to_numpy()
    params = selected_params or spec.grid[0]

    # Validation-only calibration and thresholds: inner capture-grouped out-of-fold scores.
    calibration, thresholds, val_note = None, {}, None
    try:
        folds = [f for f in make_folds(df, "CAPTURE_GROUP_KFOLD", seed=seed + 7, n_splits=3) if f.two_class_test]
        oof = np.full(len(df), np.nan)
        for f in folds:
            s, *_ = _fit_score(model, params, cols, "onehot", X.iloc[f.train_idx], y[f.train_idx], X.iloc[f.test_idx], seed)
            oof[f.test_idx] = s
        m = ~np.isnan(oof)
        calibration = M.platt_fit(y[m], oof[m])
        cal = M.platt_apply(calibration, oof[m])
        thresholds = {f"fpr<={t}": M.threshold_for_fpr(y[m], cal, t) for t in (0.01, 0.05)}
        val_metrics = M.ranking_metrics(y[m], cal)
    except InfeasibleSplit as exc:
        val_note, val_metrics = str(exc), None

    pre = TabularPreprocessor(numeric=cols["numeric"], categorical=cols["categorical"], scale=spec.scale).fit(X)
    clf = spec.build(seed=seed, **params).fit(pre.transform(X), y)

    with _lock:
        reg = load_registry(path)
        model_id = f"etth-{track.lower()}-{model}"
        prev = find(reg, model_id)
        version = (prev["version"] + 1) if prev else 1
        rel_dir = Path("artifacts") / model_id / f"v{version}"
        meta = {"model_id": model_id, "version": version, "track": track, "schema_fingerprint": schema_fingerprint(track)}
        hashes = export_model(pre, clf, ROOT / rel_dir, meta, calibration)
        entry = {
            "model_id": model_id, "version": version, "track": track, "estimator": model, "params": params,
            "status": "CANDIDATE", "research_status": RESEARCH_STATUS, "created_at": _now(),
            "fingerprint_implementations": _fingerprint_implementations(df, cols),
            "feature_schema": {"schema_version": SCHEMA_VERSION, "fingerprint": schema_fingerprint(track),
                               "numeric": cols["numeric"], "categorical": cols["categorical"],
                               "population": TRACKS[track].population},
            "missing_feature_policy": ("REJECT: every required input column must be present in the flow record; a NaN value "
                                       "is accepted only where it means 'undefined for this flow' and is median-imputed with a "
                                       "missing indicator exactly as in training. Records lacking the track's fingerprint are not scored."),
            "training": {"dataset": dataset_fingerprint(), "rows": int(len(df)), "positives": int(y.sum()),
                         "negatives": int((y == 0).sum()), "captures": sorted(df["capture_id"].unique().tolist()),
                         "datasets": sorted(df["dataset_id"].unique().tolist()), "seed": seed},
            "evaluation": {"experiments": evaluation_experiments,
                           "protocol_of_reference": "CAPTURE_GROUP_KFOLD (nested selection)",
                           "inner_validation_for_calibration": val_metrics, "validation_note": val_note},
            "calibration": {"status": "PLATT_ON_INNER_CAPTURE_OOF" if calibration else "UNCALIBRATED", "params": calibration},
            "thresholds": thresholds,
            "ood_reference": _ood_reference(X, cols),
            "known_vocab": {c: pre.state_["categorical"][c].get("vocab") for c in cols["categorical"]},
            "limitations": limitations or DEFAULT_LIMITATIONS,
            "artifact": {"format": "etth-tabular-model/1", "path": rel_dir.as_posix(), "sha256": hashes},
        }
        reg["models"].append(entry)
        save_registry(reg, path)
    return entry


def most_selected_params(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    counts = (record.get("metrics") or {}).get("selected_params_counts") or {}
    if not counts:
        return None
    import ast
    best = Counter(counts).most_common(1)[0][0]
    return ast.literal_eval(best)


def _fingerprint_implementations(df, cols) -> Dict[str, Any]:
    """Record which fingerprint implementation produced the training values, so inference can refuse
    fingerprints from any other implementation. Corpus v3 carries no tag: its 'ja4' is ETTH v1."""
    from pipeline.canonical_flow import JA4_VERSION_BY_IMPLEMENTATION, LEGACY_MODEL_JA4
    out: Dict[str, Any] = {}
    if "ja4" in cols["categorical"]:
        impls = sorted(df["ja4_implementation"].dropna().unique()) if "ja4_implementation" in df else []
        if len(impls) > 1:
            raise ModelRegistryError(f"training data mixes JA4 implementations {impls}")
        if impls:
            vers = sorted(df["ja4_version"].dropna().unique()) if "ja4_version" in df else []
            if len(vers) > 1:
                raise ModelRegistryError(f"training data mixes JA4 versions {vers}")
            out["ja4"] = {"implementation": impls[0],
                          "version": vers[0] if vers else JA4_VERSION_BY_IMPLEMENTATION.get(impls[0])}
        else:
            out["ja4"] = dict(LEGACY_MODEL_JA4)
    if "ja3_hash" in cols["categorical"]:
        out["ja3"] = {"implementation": "JA3_MD5_GREASE_FILTERED", "version": "pipeline.tls_fingerprinting.generate_ja3"}
    return out
