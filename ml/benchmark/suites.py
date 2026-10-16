"""
Benchmark suite definitions.

Every suite is EXPLORATORY: the current corpus has one source per class at the dataset
level, so no suite can provide confirmatory evidence of generalisation. A confirmatory suite
requires an independent source that has never been used in any exploratory run
(see CONFIRMATORY_POLICY below); none is available, so confirmatory evaluation is BLOCKED.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import pandas as pd

from ml.benchmark.comparisons import primary_family
from ml.benchmark.registry import Suite, config_hash, load_experiment
from ml.benchmark.runner import DEFAULT_PER_CAPTURE_CAP, experiment_config, load_benchmark_frame, run_configuration
from ml.evaluation.splits import capture_fold_assignment

logger = logging.getLogger(__name__)

CANONICAL = ["A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"]
PAIRED = ["A_FLOW@JA3POP", "A_FLOW@JA4POP"]
ABLATION = ["A0_FLOW_STRICT", "P_AVAILABILITY_PROBE"]
PRIMARY_MODEL = "random_forest"   # declared before any Phase 9 result was seen

SUITES: Dict[str, Dict[str, Any]] = {
    "pooled_capture_cv": {
        "description": "All admitted captures; whole capture sessions held out (stratified group 5-fold).",
        "datasets": None, "protocol": "CAPTURE_GROUP_KFOLD", "tracks": CANONICAL + PAIRED + ABLATION,
        "models": ["dummy_prior", "logreg", "random_forest", "hist_gb"], "encodings": ["onehot"]},
    "matched_lab_capture_cv": {
        "description": "Least-confounded subset: DS-009 malware and DS-011 benign captures from the same laboratory and period.",
        "datasets": ["DS-009", "DS-011"], "protocol": "CAPTURE_GROUP_KFOLD", "tracks": CANONICAL + PAIRED + ABLATION,
        "models": ["dummy_prior", "logreg", "random_forest", "hist_gb"], "encodings": ["onehot"]},
    "leave_one_source_out": {
        "description": "Each dataset held out in turn; single-class test folds report detection rate or false-positive rate.",
        "datasets": None, "protocol": "LEAVE_ONE_SOURCE_OUT", "tracks": CANONICAL,
        "models": ["logreg", "random_forest", "hist_gb"], "encodings": ["onehot"]},
    "leave_one_family_out": {
        "description": "Each malware family group held out with one rotating benign capture.",
        "datasets": None, "protocol": "LEAVE_ONE_FAMILY_OUT", "tracks": ["A_FLOW", "D_JA3_FLOW", "E_JA4_FLOW"],
        "models": ["random_forest", "hist_gb"], "encodings": ["onehot"]},
    "legacy_behavioral_holdout": {
        "description": "Phase 7 protocol (GroupShuffleSplit on behavioral_hash, seed 42) for continuity; captures leak across sides.",
        "datasets": None, "protocol": "BEHAVIORAL_HOLDOUT", "tracks": CANONICAL,
        "models": ["logreg", "random_forest"], "encodings": ["onehot"]},
    "encoding_ablation": {
        "description": "Fingerprint encoding strategies (one-hot, train-frequency, hashing) under capture-grouped CV.",
        "datasets": None, "protocol": "CAPTURE_GROUP_KFOLD", "tracks": ["B_JA3", "C_JA4"],
        "models": ["logreg"], "encodings": ["onehot", "frequency", "hashing"]},
    "source_identifiability": {
        "description": "Diagnostic, not detection: can features tell the two MALICIOUS sources (DS-008 vs DS-009) apart?",
        "datasets": ["DS-008", "DS-009"], "task": "SOURCE_DS-008_VS_DS-009", "protocol": "CAPTURE_GROUP_KFOLD",
        "tracks": ["A_FLOW", "C_JA4", "E_JA4_FLOW"], "models": ["random_forest"], "encodings": ["onehot"]},
}

CONFIRMATORY_POLICY = {
    "status": "BLOCKED",
    "rule": "A confirmatory evaluation must use at least one benign and one malicious source that were never used in any "
            "exploratory run, evaluated once with a configuration frozen in advance.",
    "reason": "All currently admitted sources (DS-008, DS-009, DS-011) are used in exploratory suites.",
}


def suite_frame(spec: Dict[str, Any], seed: int = 42) -> pd.DataFrame:
    df = load_benchmark_frame(spec.get("datasets"), per_capture_cap=spec.get("per_capture_cap", DEFAULT_PER_CAPTURE_CAP), seed=seed)
    task = spec.get("task")
    if task == "SOURCE_DS-008_VS_DS-009":
        df = df.copy()
        df["detection_label_y"] = df["y"]
        df["y"] = (df["dataset_id"] == "DS-008").astype(int)
        # family_group is irrelevant for this task; keep for per-group reporting only
    return df


def run_suite(name: str, seed: int = 42, n_boot: int = 1000, models: Optional[List[str]] = None,
              tracks: Optional[List[str]] = None, suite_id: Optional[str] = None) -> Dict[str, Any]:
    spec = dict(SUITES[name])
    if models:
        spec["models"] = models
    if tracks:
        spec["tracks"] = tracks
    cfg = {**spec, "seed": seed, "n_boot": n_boot}
    suite = Suite(name, cfg, stage="EXPLORATORY", suite_id=suite_id)
    df = suite_frame(spec, seed=seed)
    suite.record["evaluation_population"] = {
        "per_capture_cap": spec.get("per_capture_cap", DEFAULT_PER_CAPTURE_CAP), "rows": int(len(df)),
        "rows_by_dataset": {k: int(v) for k, v in df.groupby("dataset_id").size().items()},
        "positives": int(df["y"].sum()), "negatives": int((df["y"] == 0).sum()), "captures": int(df["capture_id"].nunique())}
    done = suite.completed_hashes()
    capture_assignment = None
    if spec["protocol"] == "CAPTURE_GROUP_KFOLD":
        capture_assignment = capture_fold_assignment(df[["capture_id", "y"]].drop_duplicates(), 5, seed)
        suite.record["capture_fold_assignment"] = capture_assignment
    records = []
    for track in spec["tracks"]:
        for model in spec["models"]:
            for enc in spec["encodings"]:
                extra = {"per_capture_cap": spec.get("per_capture_cap", DEFAULT_PER_CAPTURE_CAP),
                         **({"task": spec["task"]} if spec.get("task") else {})}
                probe_cfg = experiment_config(track, spec["protocol"], model, enc, seed, n_boot, extra)
                h = config_hash(probe_cfg)
                if h in done:
                    logger.info("Skipping completed %s/%s/%s (resume)", track, model, enc)
                    records.append(load_experiment(suite.suite_id, done[h]))
                    continue
                logger.info("Running %s | %s | %s | %s", name, track, model, enc)
                rec = run_configuration(suite, df, track, spec["protocol"], model, encoding=enc, seed=seed,
                                        capture_assignment=capture_assignment, n_boot=n_boot,
                                        extra_cfg=extra)
                records.append(rec)
    summary = {"experiments": [_row(r) for r in records]}
    if not spec.get("task") and spec["protocol"] in ("CAPTURE_GROUP_KFOLD", "BEHAVIORAL_HOLDOUT"):
        summary["paired_contrasts"] = {m: primary_family(records, m, spec["protocol"], n_boot=n_boot)
                                       for m in spec["models"] if m != "dummy_prior"}
        summary["primary_model"] = PRIMARY_MODEL
    (suite.dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    status = "COMPLETED" if all(r.get("status") in ("COMPLETED", "INFEASIBLE") for r in records) else "COMPLETED_WITH_FAILURES"
    suite.finish(status, summary={"n_experiments": len(records),
                                  "statuses": pd.Series([r.get("status") for r in records]).value_counts().to_dict()})
    return {"suite_id": suite.suite_id, "status": status, "summary": summary}


def _row(r: Dict[str, Any]) -> Dict[str, Any]:
    m = r.get("metrics") or {}
    pooled = m.get("pooled_calibrated") or {}
    boot = (m.get("bootstrap") or {}).get("average_precision") or {}
    thr = (m.get("at_validation_thresholds") or {}).get("pred@fpr<=0.01") or {}
    cov = r.get("coverage") or {}
    return {"experiment_id": r.get("experiment_id"), "status": r.get("status"), "error": r.get("error"),
            **{k: r["config"].get(k) for k in ("track", "model", "encoding", "protocol")},
            "population_rows": cov.get("population_rows"), "coverage": cov.get("coverage"),
            "n_pos": pooled.get("n_pos"), "n_neg": pooled.get("n_neg"),
            "average_precision": pooled.get("average_precision"), "ap_ci": [boot.get("ci_low"), boot.get("ci_high")],
            "ap_ci_status": boot.get("status"), "roc_auc": pooled.get("roc_auc"), "brier": pooled.get("brier"),
            "ece_15bin": pooled.get("ece_15bin"),
            "recall_at_val_fpr_0.01": thr.get("recall"), "test_fpr_at_val_fpr_0.01": thr.get("fpr"),
            "per_source": m.get("per_source"),
            "latency_ms_per_flow": ((m.get("cost") or {}).get("latency_ms_per_flow_mean") or {}).get("mean")}
