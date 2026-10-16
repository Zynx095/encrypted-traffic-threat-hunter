"""
Paired incremental-value comparisons between tracks.

Pre-declared primary contrast family (per suite, per primary model):
    A_FLOW@JA3POP -> D_JA3_FLOW     does JA3 add to flow features?        (same rows, same folds)
    A_FLOW@JA4POP -> E_JA4_FLOW     does JA4 add to flow features?        (same rows, same folds)
    B_JA3         -> D_JA3_FLOW     does flow add to JA3?                 (same rows, same folds)
    C_JA4         -> E_JA4_FLOW     does flow add to JA4?                 (same rows, same folds)
Each contrast is evaluated only on the intersection of the two experiments' out-of-fold rows,
with a paired capture-level bootstrap of the difference (B - A). Holm correction is applied
across the four contrasts. A non-significant difference is reported as "no evidence of a
difference", never as equivalence (no equivalence margin was pre-registered).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pandas as pd

from ml.benchmark.registry import PROJECT_ROOT
from ml.evaluation import metrics as M
from ml.evaluation.uncertainty import holm, paired_group_bootstrap

PRIMARY_CONTRASTS = [
    ("A_FLOW@JA3POP", "D_JA3_FLOW", "JA3 added to flow"),
    ("A_FLOW@JA4POP", "E_JA4_FLOW", "JA4 added to flow"),
    ("B_JA3", "D_JA3_FLOW", "flow added to JA3"),
    ("C_JA4", "E_JA4_FLOW", "flow added to JA4"),
]


def _ap(y, s):
    return M.ranking_metrics(y, s)["average_precision"]


def _load_predictions(record: Dict[str, Any]) -> Optional[pd.DataFrame]:
    art = record.get("artifacts", {}).get("predictions.parquet")
    if not art:
        return None
    return pd.read_parquet(PROJECT_ROOT / art["path"])


def compare(rec_a: Dict[str, Any], rec_b: Dict[str, Any], label: str, n_boot: int = 1000, seed: int = 42) -> Dict[str, Any]:
    pa, pb = _load_predictions(rec_a), _load_predictions(rec_b)
    out = {"contrast": label, "experiment_a": rec_a["experiment_id"], "experiment_b": rec_b["experiment_id"],
           "track_a": rec_a["config"]["track"], "track_b": rec_b["config"]["track"]}
    if pa is None or pb is None:
        out["status"] = "NOT_RUN"
        return out
    j = pa.merge(pb[["corpus_index", "fold", "score_calibrated"] + [c for c in pb.columns if c.startswith("pred@")]],
                 on="corpus_index", suffixes=("_a", "_b"))
    if (j["fold_a"] != j["fold_b"]).any():
        out["status"] = "INVALID"
        out["reason"] = "Paired rows were evaluated in different folds."
        return out
    out["shared_rows"] = int(len(j))
    out["rows_a_only"] = int(len(pa) - len(j))
    out["rows_b_only"] = int(len(pb) - len(j))
    out["average_precision"] = paired_group_bootstrap(j, _ap, "score_calibrated_a", "score_calibrated_b",
                                                      n_boot=n_boot, seed=seed)
    thr = "pred@fpr<=0.01"
    if f"{thr}_a" in j and f"{thr}_b" in j and (j[f"{thr}_a"] >= 0).all() and (j[f"{thr}_b"] >= 0).all():
        def recall(y, p):
            return float(p[y == 1].mean()) if (y == 1).any() else None

        def fpr(y, p):
            return float(p[y == 0].mean()) if (y == 0).any() else None
        out["recall_at_val_fpr_0.01"] = paired_group_bootstrap(j, recall, f"{thr}_a", f"{thr}_b", n_boot=n_boot, seed=seed)
        out["test_fpr_at_val_fpr_0.01"] = paired_group_bootstrap(j, fpr, f"{thr}_a", f"{thr}_b", n_boot=n_boot, seed=seed)
    else:
        out["recall_at_val_fpr_0.01"] = {"status": "UNAVAILABLE", "reason": "validation thresholds missing in a fold"}
    cost_a = rec_a.get("metrics", {}).get("cost", {})
    cost_b = rec_b.get("metrics", {}).get("cost", {})
    out["cost"] = {"latency_ms_per_flow_a": (cost_a.get("latency_ms_per_flow_mean") or {}).get("mean"),
                   "latency_ms_per_flow_b": (cost_b.get("latency_ms_per_flow_mean") or {}).get("mean"),
                   "fit_seconds_a": (cost_a.get("fit_seconds_mean") or {}).get("mean"),
                   "fit_seconds_b": (cost_b.get("fit_seconds_mean") or {}).get("mean")}
    out["status"] = "COMPLETED"
    return out


def primary_family(records: List[Dict[str, Any]], model: str, protocol: str, n_boot: int = 1000) -> Dict[str, Any]:
    by_track = {r["config"]["track"]: r for r in records
                if r.get("status") == "COMPLETED" and r["config"]["model"] == model and r["config"]["protocol"] == protocol
                and r["config"].get("encoding", "onehot") == "onehot"}
    results = []
    for a, b, label in PRIMARY_CONTRASTS:
        if a in by_track and b in by_track:
            results.append(compare(by_track[a], by_track[b], label, n_boot=n_boot))
        else:
            results.append({"contrast": label, "track_a": a, "track_b": b, "status": "NOT_RUN",
                            "reason": "one of the experiments is missing or did not complete"})
    pvals = {r["contrast"]: (r.get("average_precision") or {}).get("p_value_bootstrap") for r in results}
    adj = holm(pvals)
    for r in results:
        r["holm"] = adj.get(r["contrast"])
        ap = r.get("average_precision") or {}
        if r.get("status") != "COMPLETED":
            r["interpretation"] = "NOT_RUN"
        elif ap.get("status") == "INSUFFICIENT_GROUPS":
            r["interpretation"] = "INSUFFICIENT_EVIDENCE (too few independent captures for an interval)"
        elif ap.get("ci_low") is not None and ap["ci_low"] > 0 and (r["holm"] or {}).get("reject"):
            r["interpretation"] = "AP higher for B than A (Holm-adjusted); exploratory, source-confounded data"
        elif ap.get("ci_high") is not None and ap["ci_high"] < 0 and (r["holm"] or {}).get("reject"):
            r["interpretation"] = "AP lower for B than A (Holm-adjusted); exploratory, source-confounded data"
        else:
            r["interpretation"] = "No evidence of a difference (this is not evidence of equivalence)"
    return {"model": model, "protocol": protocol, "contrasts": results, "multiple_comparison": "Holm over 4 primary contrasts",
            "alpha": 0.05}
