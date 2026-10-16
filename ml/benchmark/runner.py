"""
Phase 9 benchmark runner.

For one (track, protocol, model, encoding) configuration:
  1. restrict the corpus to the track population (documented, coverage reported);
  2. build outer folds with the requested protocol (no behavioural group crosses a fold);
  3. inside each outer TRAINING fold: nested selection over the model's pre-declared grid with
     an inner grouped CV, using average precision; the inner out-of-fold scores of the selected
     configuration provide (a) a Platt calibrator and (b) decision thresholds for target FPRs;
  4. refit on the full outer training fold, score the outer test fold once;
  5. persist per-fold metrics, out-of-fold predictions, timings and a pooled summary with
     capture-level bootstrap intervals.
The outer test fold is never used for selection, calibration or thresholds.
"""
from __future__ import annotations

import hashlib
import logging
import time
import traceback
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import psutil

from ml.benchmark.registry import Experiment, Suite
from ml.estimators.preprocessing import TabularPreprocessor
from ml.estimators.zoo import MODEL_SPECS
from ml.evaluation import metrics as M
from ml.evaluation.splits import Fold, InfeasibleSplit, make_folds
from ml.evaluation.uncertainty import group_bootstrap
from ml.features.governance import TRACKS, assert_model_safe, population_mask, schema_fingerprint, track_columns

logger = logging.getLogger(__name__)

GROUP_COLUMNS = ["capture_id", "behavioral_hash", "dataset_id", "family_group", "collection_date"]
INNER_FOLDS = 3
THRESHOLD_FPRS = (0.01, 0.05)


DEFAULT_PER_CAPTURE_CAP = 4000


def capture_balanced_sample(df: pd.DataFrame, cap: Optional[int], seed: int = 42) -> pd.DataFrame:
    """
    Evaluation-population definition: at most `cap` flows per capture, drawn uniformly at random
    inside each capture (label-independent, deterministic). Captures range from 9 to 123,497
    flows; without a cap a handful of long malware captures would dominate every pooled metric
    and the compute budget. Captures smaller than the cap are kept whole.
    """
    if not cap:
        return df.reset_index(drop=True)
    parts = []
    for cid, g in df.groupby("capture_id", sort=True):
        if len(g) > cap:
            g = g.sample(n=cap, random_state=seed + (int(hashlib.sha256(cid.encode()).hexdigest(), 16) % 10_000))
        parts.append(g)
    return pd.concat(parts).sort_values("corpus_index").reset_index(drop=True)


def load_benchmark_frame(datasets: Optional[List[str]] = None, per_capture_cap: Optional[int] = None,
                         seed: int = 42) -> pd.DataFrame:
    """Corpus rows with binary target y and grouping columns (grouping columns never reach X)."""
    from pipeline.corpus.builder import load_corpus
    flows, prov = load_corpus()
    df = flows.merge(prov[["corpus_index"] + [c for c in GROUP_COLUMNS if c in prov.columns]], on="corpus_index", how="left")
    df["y"] = df["label"].map(lambda v: 1 if "MALICIOUS" in str(v).upper() else 0).astype(int)
    if datasets:
        df = df[df["dataset_id"].isin(datasets)]
    return capture_balanced_sample(df, per_capture_cap, seed)


def _matrix(df: pd.DataFrame, cols: Dict[str, List[str]]) -> pd.DataFrame:
    use = cols["numeric"] + cols["categorical"]
    assert_model_safe(use)
    X = df[use].copy()
    for c in cols["numeric"]:
        if X[c].dtype == bool or X[c].dtype == object:
            X[c] = pd.to_numeric(X[c].map(lambda v: float(v) if v is not None and v == v else np.nan), errors="coerce")
    return X


def _fit_score(model: str, params: Dict[str, Any], cols, encoding: str, X_tr, y_tr, X_te, seed: int):
    spec = MODEL_SPECS[model]
    pre = TabularPreprocessor(numeric=cols["numeric"], categorical=cols["categorical"], scale=spec.scale,
                              encoding=encoding).fit(X_tr)
    clf = spec.build(seed=seed, **params)
    Z_tr = pre.transform(X_tr)
    t0 = time.perf_counter()
    clf.fit(Z_tr, y_tr)
    fit_s = time.perf_counter() - t0
    t1 = time.perf_counter()
    s = clf.predict_proba(pre.transform(X_te))[:, list(clf.classes_).index(1)] if 1 in clf.classes_ else np.zeros(len(X_te))
    pred_s = time.perf_counter() - t1
    return s, pre, clf, fit_s, pred_s


def _inner_folds(df_tr: pd.DataFrame, protocol: str, seed: int) -> List[Fold]:
    """Inner validation folds that mirror the outer protocol's grouping unit."""
    inner_protocol = "BEHAVIORAL_GROUP_KFOLD" if protocol.startswith("BEHAVIORAL") else "CAPTURE_GROUP_KFOLD"
    return make_folds(df_tr, inner_protocol, seed=seed + 1, n_splits=INNER_FOLDS)


def nested_select(df_tr: pd.DataFrame, X_tr: pd.DataFrame, model: str, cols, encoding: str, protocol: str,
                  seed: int) -> Dict[str, Any]:
    spec = MODEL_SPECS[model]
    try:
        inner = [f for f in _inner_folds(df_tr, protocol, seed) if f.two_class_test and len(f.train_idx)]
    except InfeasibleSplit as exc:
        inner, reason = [], str(exc)
    else:
        reason = "no inner fold with both classes" if not inner else None
    if not inner:
        return {"params": spec.grid[0], "inner_status": "INFEASIBLE", "inner_reason": reason,
                "calibration": None, "thresholds": {}, "grid_scores": []}
    y = df_tr["y"].to_numpy()
    grid_scores = []
    best = None
    for params in spec.grid:
        oof = np.full(len(df_tr), np.nan)
        aps = []
        for f in inner:
            s, *_ = _fit_score(model, params, cols, encoding, X_tr.iloc[f.train_idx], y[f.train_idx],
                               X_tr.iloc[f.test_idx], seed)
            oof[f.test_idx] = s
            aps.append(M.ranking_metrics(y[f.test_idx], s)["average_precision"])
        mean_ap = float(np.mean([a for a in aps if a is not None])) if aps else float("nan")
        grid_scores.append({"params": params, "inner_mean_ap": mean_ap, "inner_fold_ap": aps})
        if best is None or mean_ap > best[0]:
            best = (mean_ap, params, oof)
    _, params, oof = best
    m = ~np.isnan(oof)
    cal = M.platt_fit(y[m], oof[m])
    cal_oof = M.platt_apply(cal, oof[m])
    thresholds = {f"fpr<={t}": M.threshold_for_fpr(y[m], cal_oof, t) for t in THRESHOLD_FPRS}
    return {"params": params, "inner_status": "OK", "inner_reason": None, "calibration": cal,
            "thresholds": thresholds, "grid_scores": grid_scores, "inner_validation_rows": int(m.sum())}


def experiment_config(track: str, protocol: str, model: str, encoding: str, seed: int, n_boot: int,
                      extra_cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The exact configuration that identifies an experiment (its hash drives resumption)."""
    return {"track": track, "protocol": protocol, "model": model, "encoding": encoding, "seed": seed,
            "feature_schema": schema_fingerprint(track), "population": TRACKS[track].population,
            "inner_folds": INNER_FOLDS, "threshold_fprs": list(THRESHOLD_FPRS), "n_boot": n_boot, **(extra_cfg or {})}


def run_configuration(suite: Suite, df_all: pd.DataFrame, track: str, protocol: str, model: str,
                      encoding: str = "onehot", seed: int = 42, folds_override: Optional[List[Fold]] = None,
                      capture_assignment: Optional[Dict[str, int]] = None, n_boot: int = 1000,
                      population_note: str = "", extra_cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = experiment_config(track, protocol, model, encoding, seed, n_boot, extra_cfg)
    exp = Experiment(suite, cfg)
    try:
        cols = track_columns(track)
        mask = population_mask(df_all, track)
        df = df_all.loc[mask].reset_index(drop=True)
        coverage = {"population_rows": int(len(df)), "corpus_rows": int(len(df_all)),
                    "coverage": round(len(df) / max(len(df_all), 1), 6),
                    "population_pos": int(df["y"].sum()), "population_neg": int((df["y"] == 0).sum()),
                    "population_captures": int(df["capture_id"].nunique()),
                    "excluded_rows_by_label": {str(k): int(v) for k, v in df_all.loc[~mask, "y"].value_counts().items()},
                    "note": population_note}
        if df["y"].nunique() < 2:
            return exp.finish("INFEASIBLE", error="Track population contains a single class", extra={"coverage": coverage})
        X = _matrix(df, cols)
        y = df["y"].to_numpy()
        try:
            folds = folds_override if folds_override is not None else make_folds(
                df, protocol, seed=seed, capture_assignment=capture_assignment)
        except InfeasibleSplit as exc:
            return exp.finish("INFEASIBLE", error=str(exc), extra={"coverage": coverage})

        fold_results, preds = [], []
        selected = Counter()
        rss0 = psutil.Process().memory_info().rss
        for f in folds:
            summ = f.summary(df)
            if len(f.train_idx) == 0 or df["y"].iloc[f.train_idx].nunique() < 2:
                summ["status"] = "INFEASIBLE"
                summ["reason"] = f.held_out.get("infeasible", "single-class training fold")
                fold_results.append(summ)
                continue
            df_tr = df.iloc[f.train_idx].reset_index(drop=True)
            sel = nested_select(df_tr, X.iloc[f.train_idx].reset_index(drop=True), model, cols, encoding, protocol, seed)
            selected[str(sel["params"])] += 1
            s, pre, clf, fit_s, pred_s = _fit_score(model, sel["params"], cols, encoding, X.iloc[f.train_idx],
                                                    y[f.train_idx], X.iloc[f.test_idx], seed)
            s_cal = M.platt_apply(sel["calibration"], s)
            yt = y[f.test_idx]
            summ.update({"status": "COMPLETED", "selected_params": sel["params"], "inner_status": sel["inner_status"],
                         "inner_reason": sel["inner_reason"], "grid_scores": sel["grid_scores"],
                         "calibration": sel["calibration"], "thresholds": sel["thresholds"],
                         "fit_seconds": round(fit_s, 4), "predict_seconds": round(pred_s, 4),
                         "latency_ms_per_flow": round(1000 * pred_s / max(len(f.test_idx), 1), 5),
                         "throughput_flows_per_s": round(len(f.test_idx) / pred_s, 1) if pred_s > 0 else None,
                         "n_features_out": len(pre.feature_names_out_),
                         "ranking_raw": M.ranking_metrics(yt, s), "ranking_calibrated": M.ranking_metrics(yt, s_cal),
                         "at_validation_thresholds": {k: (M.threshold_metrics(yt, s_cal, thr) if thr is not None else None)
                                                      for k, thr in sel["thresholds"].items()},
                         "at_0.5_uncalibrated": M.threshold_metrics(yt, s, 0.5)})
            fold_results.append(summ)
            pf = df.iloc[f.test_idx][["corpus_index", "y", "capture_id", "dataset_id", "family_group"]].copy()
            pf["fold"] = f.name
            pf["score"] = s
            pf["score_calibrated"] = s_cal
            for k, thr in sel["thresholds"].items():
                pf[f"pred@{k}"] = (s_cal >= thr).astype(int) if thr is not None else -1
            preds.append(pf)
        rss1 = psutil.Process().memory_info().rss

        if not preds:
            return exp.finish("INFEASIBLE", error="No fold could be trained", extra={"coverage": coverage, "folds": fold_results})
        P = pd.concat(preds, ignore_index=True)
        exp.save_artifact("predictions.parquet", P)
        exp.save_artifact("folds.json", fold_results)
        summary = summarize_predictions(P, n_boot=n_boot, seed=seed)
        done = [r for r in fold_results if r.get("status") == "COMPLETED"]
        summary["per_fold"] = {
            "completed_folds": len(done), "total_folds": len(fold_results),
            "two_class_test_folds": sum(1 for r in done if r["test_pos"] and r["test_neg"]),
            "average_precision": _mean_sd([r["ranking_calibrated"]["average_precision"] for r in done]),
            "roc_auc": _mean_sd([r["ranking_calibrated"]["roc_auc"] for r in done]),
        }
        summary["cost"] = {"fit_seconds_mean": _mean_sd([r["fit_seconds"] for r in done]),
                           "latency_ms_per_flow_mean": _mean_sd([r["latency_ms_per_flow"] for r in done]),
                           "rss_delta_mb": round((rss1 - rss0) / 2**20, 1)}
        summary["selected_params_counts"] = dict(selected)
        summary["purged_train_rows_total"] = int(sum(r.get("purged_train_rows", 0) for r in fold_results))
        if any(r.get("inner_status") == "INFEASIBLE" for r in done):
            exp.warn("Inner validation infeasible in at least one fold: default grid point used, no calibration or thresholds there.")
        return exp.finish("COMPLETED", metrics=summary, extra={"coverage": coverage})
    except Exception as exc:  # recorded, never swallowed silently
        logger.exception("Experiment %s failed", exp.experiment_id)
        return exp.finish("FAILED", error=f"{type(exc).__name__}: {exc}", extra={"traceback": traceback.format_exc()[-4000:]})


def _mean_sd(vals):
    v = [x for x in vals if x is not None]
    if not v:
        return None
    return {"mean": float(np.mean(v)), "sd": float(np.std(v, ddof=1)) if len(v) > 1 else None, "n": len(v)}


def summarize_predictions(P: pd.DataFrame, n_boot: int = 1000, seed: int = 42) -> Dict[str, Any]:
    """Pooled out-of-fold summary. Scores pooled across fold models use the validation-calibrated score."""
    y, s = P["y"].to_numpy(), P["score_calibrated"].to_numpy()
    out: Dict[str, Any] = {"pooled_calibrated": M.ranking_metrics(y, s)}

    def ap(df):
        return M.ranking_metrics(df["y"].to_numpy(), df["score_calibrated"].to_numpy())["average_precision"]

    def roc(df):
        return M.ranking_metrics(df["y"].to_numpy(), df["score_calibrated"].to_numpy())["roc_auc"]

    out["bootstrap"] = {"average_precision": group_bootstrap(P, ap, n_boot=n_boot, seed=seed),
                        "roc_auc": group_bootstrap(P, roc, n_boot=n_boot, seed=seed)}
    thr_cols = [c for c in P.columns if c.startswith("pred@")]
    out["at_validation_thresholds"] = {}
    for c in thr_cols:
        valid = P[c] >= 0
        if not valid.any():
            out["at_validation_thresholds"][c] = None
            continue
        sub = P[valid]
        yy, pp = sub["y"].to_numpy(), sub[c].to_numpy()
        tp = int(((pp == 1) & (yy == 1)).sum()); fp = int(((pp == 1) & (yy == 0)).sum())
        fn = int(((pp == 0) & (yy == 1)).sum()); tn = int(((pp == 0) & (yy == 0)).sum())
        npos, nneg = tp + fn, tn + fp
        block = {"n": int(len(sub)), "n_pos": npos, "n_neg": nneg, "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
                 "recall": tp / npos if npos else None, "fpr": fp / nneg if nneg else None,
                 "precision": tp / (tp + fp) if (tp + fp) else None,
                 "specificity": tn / nneg if nneg else None}
        if npos and nneg:
            from sklearn.metrics import balanced_accuracy_score, f1_score, matthews_corrcoef
            block.update(f1=float(f1_score(yy, pp, zero_division=0)), balanced_accuracy=float(balanced_accuracy_score(yy, pp)),
                         mcc=float(matthews_corrcoef(yy, pp)))
        out["at_validation_thresholds"][c] = block
    out["per_capture"] = {cid: {"y": int(g["y"].iloc[0]), "n": int(len(g)), "mean_score": float(g["score_calibrated"].mean()),
                                **{c: float((g[c] == 1).mean()) for c in thr_cols if (g[c] >= 0).all()}}
                          for cid, g in P.groupby("capture_id")}
    out["per_source"] = {}
    for src, g in P.groupby("dataset_id"):
        blk = {"n": int(len(g)), "n_pos": int(g["y"].sum()), "mean_score": float(g["score_calibrated"].mean())}
        for c in thr_cols:
            if (g[c] >= 0).all():
                rate = float((g[c] == 1).mean())
                blk["detection_rate" if g["y"].iloc[0] == 1 else "false_positive_rate"] = blk.get(
                    "detection_rate" if g["y"].iloc[0] == 1 else "false_positive_rate", {})
                blk["detection_rate" if g["y"].iloc[0] == 1 else "false_positive_rate"][c] = rate
        out["per_source"][src] = blk
    if P["family_group"].notna().any():
        out["per_family_detection_rate"] = {
            fam: {c: float((g[c] == 1).mean()) for c in thr_cols if (g[c] >= 0).all()} | {"n": int(len(g))}
            for fam, g in P[P["y"] == 1].groupby("family_group")}
    return out
