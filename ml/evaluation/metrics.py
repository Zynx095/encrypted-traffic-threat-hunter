"""
Metric conventions (positive class = MALICIOUS = 1).

average_precision   sklearn.metrics.average_precision_score: step-wise sum over thresholds
                    of (R_n - R_{n-1}) * P_n. No interpolation. This is the primary ranking metric.
pr_auc_trapezoid    trapezoidal area under the PR curve (sklearn.metrics.auc on
                    precision_recall_curve). Reported only for continuity with the Phase 7 pilot;
                    it is optimistic relative to AP and the two are NOT interchangeable.
roc_auc             secondary.
threshold metrics   computed at an explicitly supplied threshold; the threshold must come from
                    validation data (see threshold_for_fpr), never from the test fold.
brier               mean squared error of the score as a probability.
ece                 expected calibration error with 15 equal-width bins on [0, 1]:
                    sum_b (n_b / n) * |mean(y)_b - mean(score)_b|.
tpr_at_fpr          descriptive ROC summary: the largest TPR whose FPR is <= target on the SAME
                    data. It is a curve property, not an achievable operating point.
Every metric block carries n, n_pos and n_neg. Metrics that are undefined for a population
(e.g. AP with no positives) are returned as None with a reason, never as 0 or 1.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

import numpy as np
from sklearn.metrics import (auc, average_precision_score, balanced_accuracy_score, brier_score_loss,
                             confusion_matrix, f1_score, matthews_corrcoef, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score, roc_curve)

ECE_BINS = 15
FPR_TARGETS = (0.001, 0.01, 0.05)


def ece(y: np.ndarray, s: np.ndarray, bins: int = ECE_BINS) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    ids = np.clip(np.digitize(s, edges[1:-1], right=True), 0, bins - 1)
    total = 0.0
    for b in range(bins):
        m = ids == b
        if m.any():
            total += m.mean() * abs(y[m].mean() - s[m].mean())
    return float(total)


def threshold_for_fpr(y_val: np.ndarray, s_val: np.ndarray, target_fpr: float) -> Optional[float]:
    """Smallest threshold whose validation FPR is <= target (predict positive if score >= threshold)."""
    neg = np.sort(s_val[y_val == 0])
    if neg.size == 0:
        return None
    k = int(np.floor(target_fpr * neg.size))          # number of negatives allowed above threshold
    if k >= neg.size:
        return float(neg[0])
    # threshold strictly above the (n-k)-th largest negative
    cut = neg[neg.size - k - 1]
    return float(np.nextafter(cut, np.inf))


def tpr_at_fpr(y: np.ndarray, s: np.ndarray, targets: Iterable[float] = FPR_TARGETS) -> Dict[str, Optional[float]]:
    if len(np.unique(y)) < 2:
        return {f"tpr@fpr={t}": None for t in targets}
    fpr, tpr, _ = roc_curve(y, s)
    return {f"tpr@fpr={t}": float(tpr[fpr <= t].max()) if (fpr <= t).any() else 0.0 for t in targets}


def threshold_metrics(y: np.ndarray, s: np.ndarray, threshold: float) -> Dict[str, Any]:
    pred = (s >= threshold).astype(int)
    n_pos, n_neg = int(y.sum()), int((y == 0).sum())
    out: Dict[str, Any] = {"threshold": float(threshold), "n": int(len(y)), "n_pos": n_pos, "n_neg": n_neg}
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    out["confusion_matrix"] = {"tn": tn, "fp": fp, "fn": fn, "tp": tp}
    out["recall"] = tp / n_pos if n_pos else None
    out["fnr"] = fn / n_pos if n_pos else None
    out["specificity"] = tn / n_neg if n_neg else None
    out["fpr"] = fp / n_neg if n_neg else None
    out["precision"] = tp / (tp + fp) if (tp + fp) else None
    if n_pos and n_neg:
        out["f1"] = float(f1_score(y, pred, zero_division=0))
        out["balanced_accuracy"] = float(balanced_accuracy_score(y, pred))
        out["mcc"] = float(matthews_corrcoef(y, pred))
    else:
        out["f1"] = out["balanced_accuracy"] = out["mcc"] = None
        out["undefined_reason"] = "single-class population: only class-conditional rates are defined"
    return out


def ranking_metrics(y: np.ndarray, s: np.ndarray) -> Dict[str, Any]:
    y = np.asarray(y).astype(int)
    s = np.asarray(s, dtype=float)
    n_pos, n_neg = int(y.sum()), int((y == 0).sum())
    out: Dict[str, Any] = {"n": int(len(y)), "n_pos": n_pos, "n_neg": n_neg,
                           "prevalence": n_pos / len(y) if len(y) else None}
    if n_pos and n_neg:
        out["average_precision"] = float(average_precision_score(y, s))
        p, r, _ = precision_recall_curve(y, s)
        out["pr_auc_trapezoid"] = float(auc(r, p))
        out["roc_auc"] = float(roc_auc_score(y, s))
        out["brier"] = float(brier_score_loss(y, np.clip(s, 0, 1)))
        out["ece_15bin"] = ece(y, np.clip(s, 0, 1))
        out.update(tpr_at_fpr(y, s))
    else:
        for k in ("average_precision", "pr_auc_trapezoid", "roc_auc", "brier", "ece_15bin"):
            out[k] = None
        out.update(tpr_at_fpr(y, s))
        out["undefined_reason"] = "ranking metrics need both classes"
        out["mean_score"] = float(s.mean()) if len(s) else None
    return out


def platt_fit(y_val: np.ndarray, s_val: np.ndarray) -> Optional[Dict[str, float]]:
    """Sigmoid calibration fitted on validation (inner out-of-fold) predictions only."""
    if len(np.unique(y_val)) < 2:
        return None
    from sklearn.linear_model import LogisticRegression
    lr = LogisticRegression(C=1e6, max_iter=1000)
    lr.fit(s_val.reshape(-1, 1), y_val)
    return {"a": float(lr.coef_[0][0]), "b": float(lr.intercept_[0])}


def platt_apply(cal: Optional[Dict[str, float]], s: np.ndarray) -> np.ndarray:
    if not cal:
        return s
    return 1.0 / (1.0 + np.exp(-(cal["a"] * s + cal["b"])))
