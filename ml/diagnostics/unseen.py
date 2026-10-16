"""
Unseen-fingerprint analysis for fingerprint tracks under capture-grouped evaluation.

For every out-of-fold prediction, decide whether the flow's fingerprint value was part of the
training fold's one-hot vocabulary (seen >= min_frequency times in training) and tabulate the
validation-threshold decisions by (class, seen/unseen). This explains how a fingerprint model
behaves on client stacks it has never observed — the realistic case for new captures.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pandas as pd

from ml.benchmark.registry import PROJECT_ROOT
from ml.evaluation.splits import make_folds
from ml.features.governance import population_mask

FP_COLUMN = {"B_JA3": "ja3_hash", "D_JA3_FLOW": "ja3_hash", "C_JA4": "ja4", "E_JA4_FLOW": "ja4"}


def unseen_analysis(df_all: pd.DataFrame, record: Dict[str, Any], suite: Dict[str, Any], min_frequency: int = 2) -> Dict[str, Any]:
    track = record["config"]["track"]
    col = FP_COLUMN.get(track)
    if col is None:
        return {"status": "NOT_APPLICABLE", "reason": f"{track} has no fingerprint input"}
    art = record["artifacts"]["predictions.parquet"]["path"]
    path = Path(art)
    P = pd.read_parquet(path if path.is_absolute() else PROJECT_ROOT / path)
    df = df_all.loc[population_mask(df_all, track)].reset_index(drop=True)
    folds = make_folds(df, suite["config"]["protocol"], seed=suite["config"]["seed"],
                       capture_assignment=suite.get("capture_fold_assignment"))
    seen_flag = {}
    for f in folds:
        if len(f.train_idx) == 0:
            continue
        counts = df[col].iloc[f.train_idx].value_counts()
        vocab = set(counts[counts >= min_frequency].index)
        for i in f.test_idx:
            seen_flag[int(df["corpus_index"].iloc[i])] = df[col].iloc[i] in vocab
    P["fingerprint_seen_in_training"] = P["corpus_index"].map(seen_flag)
    thr = "pred@fpr<=0.01"
    out: Dict[str, Any] = {"status": "COMPLETED", "track": track, "model": record["config"]["model"],
                           "experiment_id": record["experiment_id"], "min_frequency": min_frequency, "cells": []}
    for (y, seen), g in P.groupby(["y", "fingerprint_seen_in_training"]):
        cell = {"class": "MALICIOUS" if y == 1 else "BENIGN", "fingerprint_seen_in_training": bool(seen), "flows": int(len(g)),
                "captures": int(g["capture_id"].nunique()), "mean_score": float(g["score_calibrated"].mean())}
        if thr in g and (g[thr] >= 0).all():
            cell["flagged_rate_at_val_fpr_0.01"] = float((g[thr] == 1).mean())
        out["cells"].append(cell)
    ben = P[P["y"] == 0]
    out["benign_unseen_share"] = float((~ben["fingerprint_seen_in_training"].astype(bool)).mean()) if len(ben) else None
    out["interpretation"] = ("False positives concentrated in benign flows with unseen fingerprints indicate that the model "
                             "treats unfamiliar client stacks as malicious, i.e. novelty rather than maliciousness.")
    return out
