"""
Phase 10 experiment: do sequence models add detection value over strong tabular baselines?

Every model sees the SAME flows, the SAME outer capture-grouped folds (identical assignment
to the Phase 9 suites for the same datasets and seed), the SAME inner validation captures and
the SAME (deterministically subsampled) training rows:

    tab_trackA_hist_gb      Track A full-flow features, HistGradientBoosting   (strong tabular)
    tab_trackA_random_forest Track A full-flow features, RandomForest           (strong tabular)
    seqagg_logreg           summary statistics of the first max_len packets    (information-matched)
    seqagg_hist_gb          same summary statistics, HistGradientBoosting       (information-matched)
    cnn                     masked 1-D CNN on the first max_len packets
    gru                     GRU on the first max_len packets

Validation captures (held out from the outer training fold) drive early stopping, Platt
calibration and decision thresholds. The outer test fold is scored once per model.
Note: Track A features summarise the WHOLE flow, the sequence models see only its first
max_len packets, so the tabular baseline has strictly more information.
"""
from __future__ import annotations

import json
import logging
import time
import traceback
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import psutil

from ml.benchmark.comparisons import compare, interpret
from ml.benchmark.registry import PHASE10_ROOT, Experiment, Suite
from ml.benchmark.runner import DEFAULT_PER_CAPTURE_CAP, _matrix, load_benchmark_frame, summarize_predictions
from ml.estimators.preprocessing import TabularPreprocessor
from ml.estimators.zoo import MODEL_SPECS
from ml.evaluation import metrics as M
from ml.evaluation.splits import capture_fold_assignment, make_folds
from ml.evaluation.uncertainty import holm
from ml.features.governance import track_columns
from ml.sequence.dataset import CHANNELS, SequenceNormaliser, aggregate_features, build_sequences
from ml.sequence.train import predict, train_model

logger = logging.getLogger(__name__)

MAX_TRAIN_ROWS = 60000
TABULAR_MODELS = {"tab_trackA_hist_gb": ("hist_gb", {"learning_rate": 0.1, "max_leaf_nodes": 31}, "trackA"),
                  "tab_trackA_random_forest": ("random_forest", {"min_samples_leaf": 1}, "trackA"),
                  "seqagg_logreg": ("logreg", {"C": 1.0}, "seqagg"),
                  "seqagg_hist_gb": ("hist_gb", {"learning_rate": 0.1, "max_leaf_nodes": 31}, "seqagg")}
CONTRASTS = [("seqagg_hist_gb", "cnn", "CNN vs information-matched tabular"),
             ("seqagg_hist_gb", "gru", "GRU vs information-matched tabular"),
             ("tab_trackA_hist_gb", "cnn", "CNN vs full-flow tabular"),
             ("tab_trackA_hist_gb", "gru", "GRU vs full-flow tabular")]


def _subsample_by_capture(df: pd.DataFrame, idx: np.ndarray, cap: int, seed: int) -> np.ndarray:
    if len(idx) <= cap:
        return idx
    rng = np.random.default_rng(seed)
    frac = cap / len(idx)
    keep = []
    for _, g in df.iloc[idx].groupby("capture_id"):
        rows = idx[np.isin(idx, g.index.to_numpy())]
        k = max(1, int(round(len(rows) * frac)))
        keep.append(rng.choice(rows, size=min(k, len(rows)), replace=False))
    return np.sort(np.concatenate(keep))


def _validation_split(df: pd.DataFrame, train_idx: np.ndarray, seed: int):
    sub = df.iloc[train_idx]
    caps = sub[["capture_id", "y"]].drop_duplicates()
    assign = capture_fold_assignment(caps, 3, seed + 11)
    for k in sorted(set(assign.values())):
        val_caps = {c for c, f in assign.items() if f == k}
        is_val = sub["capture_id"].isin(val_caps).to_numpy()
        if sub["y"].to_numpy()[is_val].min() != sub["y"].to_numpy()[is_val].max():
            val_idx, core_idx = train_idx[is_val], train_idx[~is_val]
            val_groups = set(df["behavioral_hash"].iloc[val_idx])
            keep = ~df["behavioral_hash"].iloc[core_idx].isin(val_groups).to_numpy()
            return core_idx[keep], val_idx, sorted(val_caps), int((~keep).sum())
    raise ValueError("No validation split with both classes")


def _fit_tabular(model: str, params: Dict, X: pd.DataFrame, numeric: List[str], categorical: List[str],
                 core: np.ndarray, val: np.ndarray, test: np.ndarray, y: np.ndarray, seed: int):
    spec = MODEL_SPECS[model]
    pre = TabularPreprocessor(numeric=numeric, categorical=categorical, scale=spec.scale).fit(X.iloc[core])
    clf = spec.build(seed=seed, **params)
    t0 = time.perf_counter()
    clf.fit(pre.transform(X.iloc[core]), y[core])
    fit_s = time.perf_counter() - t0
    s_val = clf.predict_proba(pre.transform(X.iloc[val]))[:, 1]
    t1 = time.perf_counter()
    s_te = clf.predict_proba(pre.transform(X.iloc[test]))[:, 1]
    pred_s = time.perf_counter() - t1
    return s_val, s_te, {"fit_seconds": round(fit_s, 3), "latency_ms_per_flow": round(1000 * pred_s / max(len(test), 1), 5)}


def run_sequence_suite(epochs: int = 30, archs: Optional[List[str]] = None, seed: int = 42, max_len: int = 64,
                       datasets: Optional[List[str]] = None, n_boot: int = 1000,
                       per_capture_cap: int = DEFAULT_PER_CAPTURE_CAP) -> Dict[str, Any]:
    archs = archs or ["cnn", "gru"]
    name = "sequence_capture_cv" + ("_" + "_".join(d.replace("-", "") for d in datasets) if datasets else "")
    cfg = {"epochs": epochs, "archs": archs, "seed": seed, "max_len": max_len, "datasets": datasets,
           "max_train_rows": MAX_TRAIN_ROWS, "per_capture_cap": per_capture_cap, "channels": CHANNELS, "tabular": TABULAR_MODELS, "n_boot": n_boot}
    suite = Suite(name, cfg, root=PHASE10_ROOT)
    df = load_benchmark_frame(datasets, per_capture_cap=per_capture_cap, seed=seed)
    batch = build_sequences(df, max_len=max_len)
    suite.record["sequence_construction"] = {"rows": int(len(df)), "valid": int(batch.valid.sum()), "rejected": batch.reasons,
                                             "max_len": max_len, "truncated_flows": int((df["sequence_original_length"] > max_len).sum())}
    keep = np.nonzero(batch.valid)[0]
    df = df.iloc[keep].reset_index(drop=True)
    for attr in ("x", "mask", "lengths"):
        setattr(batch, attr, getattr(batch, attr)[keep])
    y = df["y"].to_numpy()
    cols = track_columns("A_FLOW")
    X_tab = _matrix(df, cols)
    X_agg = aggregate_features(batch)
    assign = capture_fold_assignment(df[["capture_id", "y"]].drop_duplicates(), 5, seed)
    folds = make_folds(df, "CAPTURE_GROUP_KFOLD", seed=seed, capture_assignment=assign)
    suite.record["capture_fold_assignment"] = assign

    model_names = list(TABULAR_MODELS) + archs
    exps = {m: Experiment(suite, {"model": m, "max_len": max_len, "epochs": epochs, "seed": seed, "datasets": datasets,
                                  "protocol": "CAPTURE_GROUP_KFOLD", "population": "ALL_FLOWS_WITH_VALID_SEQUENCE",
                                  "task": "DETECTION"}) for m in model_names}
    preds: Dict[str, List[pd.DataFrame]] = {m: [] for m in model_names}
    fold_info: Dict[str, List[Dict]] = {m: [] for m in model_names}
    interpretations: Dict[str, Any] = {}   # per-architecture saliency summaries (not the contrast reading rule)
    try:
        for f in folds:
            if not f.two_class_test:
                continue
            core, val, val_caps, purged_val = _validation_split(df, f.train_idx, seed)
            core = _subsample_by_capture(df, core, MAX_TRAIN_ROWS, seed)
            base = df.iloc[f.test_idx][["corpus_index", "y", "capture_id", "dataset_id", "family_group"]].copy()
            base["fold"] = f.name
            common = {"fold": f.name, "train_rows": int(len(core)), "val_rows": int(len(val)), "test_rows": int(len(f.test_idx)),
                      "validation_captures": val_caps, "purged_core_rows_vs_validation": purged_val,
                      "purged_train_rows_vs_test": f.purged_train_rows}

            def record(mname, s_val, s_te, extra):
                cal = M.platt_fit(y[val], s_val)
                cv, ct = M.platt_apply(cal, s_val), M.platt_apply(cal, s_te)
                thr = {f"fpr<={t}": M.threshold_for_fpr(y[val], cv, t) for t in (0.01, 0.05)}
                p = base.copy()
                p["score"], p["score_calibrated"] = s_te, ct
                for k, t in thr.items():
                    p[f"pred@{k}"] = (ct >= t).astype(int) if t is not None else -1
                preds[mname].append(p)
                fold_info[mname].append({**common, **extra, "calibration": cal, "thresholds": thr,
                                         "validation": M.ranking_metrics(y[val], cv),
                                         "test": M.ranking_metrics(y[f.test_idx], ct)})

            for mname, (model, params, feats) in TABULAR_MODELS.items():
                if feats == "trackA":
                    s_val, s_te, ex = _fit_tabular(model, params, X_tab, cols["numeric"], cols["categorical"], core, val, f.test_idx, y, seed)
                else:
                    s_val, s_te, ex = _fit_tabular(model, params, X_agg, list(X_agg.columns), [], core, val, f.test_idx, y, seed)
                record(mname, s_val, s_te, ex)

            norm = SequenceNormaliser().fit(batch, core)
            pack = lambda idx: {"x": norm.transform(batch, idx), "mask": batch.mask[idx], "lengths": batch.lengths[idx], "y": y[idx]}
            tr, va, te = pack(core), pack(val), pack(f.test_idx)
            for arch in archs:
                rss0 = psutil.Process().memory_info().rss
                res = train_model(arch, tr, va, seed=seed, epochs=epochs,
                                  checkpoint_path=exps[arch].dir / f"checkpoint_{f.name}.safetensors")
                t1 = time.perf_counter()
                s_te = predict(res["model"], te["x"], te["mask"], te["lengths"])
                pred_s = time.perf_counter() - t1
                s_val = predict(res["model"], va["x"], va["mask"], va["lengths"])
                record(arch, s_val, s_te, {"history": res["history"], "best_epoch": res["best_epoch"],
                                           "epochs_run": res["epochs_run"], "fit_seconds": res["train_seconds"],
                                           "parameters": res["parameters"], "pos_weight": res["pos_weight"],
                                           "latency_ms_per_flow": round(1000 * pred_s / max(len(f.test_idx), 1), 5),
                                           "rss_delta_mb": round((psutil.Process().memory_info().rss - rss0) / 2**20, 1),
                                           "normaliser": norm.to_dict(), "device": res["device"]})
                if not interpretations.get(arch):
                    from ml.sequence.interpret import interpret_sequence_model
                    interpretations[arch] = interpret_sequence_model(res["model"], te, fold=f.name, iat_std=norm.stats[2][1])
            logger.info("Phase 10 fold %s complete", f.name)

        results = {}
        for m in model_names:
            if not preds[m]:
                results[m] = exps[m].finish("INFEASIBLE", error="no two-class fold")
                continue
            P = pd.concat(preds[m], ignore_index=True)
            exps[m].save_artifact("predictions.parquet", P)
            exps[m].save_artifact("folds.json", fold_info[m])
            summary = summarize_predictions(P, n_boot=n_boot, seed=seed)
            summary["cost"] = {"fit_seconds_mean": {"mean": float(np.mean([x["fit_seconds"] for x in fold_info[m]]))},
                               "latency_ms_per_flow_mean": {"mean": float(np.mean([x["latency_ms_per_flow"] for x in fold_info[m]]))},
                               "parameters": fold_info[m][0].get("parameters")}
            if m in interpretations:
                exps[m].save_artifact("interpretation.json", interpretations[m])
            results[m] = exps[m].finish("COMPLETED", metrics=summary)
        contrasts = []
        for a, b, label in CONTRASTS:
            if results.get(a, {}).get("status") == "COMPLETED" and results.get(b, {}).get("status") == "COMPLETED":
                ra, rb = dict(results[a]), dict(results[b])
                ra["config"] = {**ra["config"], "track": a}
                rb["config"] = {**rb["config"], "track": b}
                contrasts.append(compare(ra, rb, label, n_boot=n_boot))
        adj = holm({c["contrast"]: (c.get("average_precision") or {}).get("p_value_bootstrap") for c in contrasts})
        for c in contrasts:
            c["holm"] = adj.get(c["contrast"])
            c["interpretation"] = interpret(c)
        summary = {"models": {m: {"status": r.get("status"), "experiment_id": r.get("experiment_id"),
                                  "average_precision": ((r.get("metrics") or {}).get("pooled_calibrated") or {}).get("average_precision"),
                                  "ap_bootstrap": ((r.get("metrics") or {}).get("bootstrap") or {}).get("average_precision"),
                                  "recall_at_val_fpr_0.01": (((r.get("metrics") or {}).get("at_validation_thresholds") or {}).get("pred@fpr<=0.01") or {}).get("recall"),
                                  "test_fpr_at_val_fpr_0.01": (((r.get("metrics") or {}).get("at_validation_thresholds") or {}).get("pred@fpr<=0.01") or {}).get("fpr"),
                                  "cost": (r.get("metrics") or {}).get("cost")} for m, r in results.items()},
                   "contrasts": contrasts, "multiple_comparison": "Holm over 4 pre-declared contrasts"}
        (suite.dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
        suite.finish("COMPLETED", summary={"models": list(results)})
        return {"suite_id": suite.suite_id, "status": "COMPLETED", "summary": summary}
    except Exception as exc:
        logger.exception("Phase 10 suite failed")
        for m, e in exps.items():
            if e.record["status"] == "RUNNING":
                e.finish("FAILED", error=f"{type(exc).__name__}: {exc}", extra={"traceback": traceback.format_exc()[-4000:]})
        suite.finish("FAILED")
        return {"suite_id": suite.suite_id, "status": "FAILED", "error": str(exc)}
