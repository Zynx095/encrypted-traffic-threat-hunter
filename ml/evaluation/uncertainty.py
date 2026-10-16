"""
Group-aware uncertainty.

Flows from the same capture are strongly correlated, so the resampling unit is the capture
(or another declared group), never the individual flow. Groups are resampled with replacement
separately within each class stratum (captures are single-class), and the metric is
recomputed on the concatenated rows.

With few independent groups a bootstrap interval is unreliable. If any stratum has fewer than
MIN_GROUPS groups the interval is withheld (status INSUFFICIENT_GROUPS). Between MIN_GROUPS
and ADEQUATE_GROUPS the interval is reported with status FEW_GROUPS and should be read as
likely too narrow.

Paired comparisons resample the SAME groups for both systems and report the distribution of
metric(B) - metric(A). The two-sided bootstrap p-value is 2 * min(P(diff <= 0), P(diff >= 0));
Holm's step-down procedure controls the family-wise error rate across a pre-declared family
of contrasts.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

import numpy as np
import pandas as pd

MIN_GROUPS = 5
ADEQUATE_GROUPS = 10


def _status(counts: Dict[int, int]) -> str:
    m = min(counts.values()) if counts else 0
    if m < MIN_GROUPS:
        return "INSUFFICIENT_GROUPS"
    if m < ADEQUATE_GROUPS:
        return "FEW_GROUPS"
    return "OK"


def _group_index(df: pd.DataFrame, group_col: str, strata_col: str):
    strata = {}
    for s, part in df.groupby(strata_col):
        groups = {g: part.index[part[group_col] == g].to_numpy() for g in part[group_col].unique()}
        strata[s] = groups
    return strata


def _resample(strata, rng) -> np.ndarray:
    rows = []
    for groups in strata.values():
        keys = list(groups.keys())
        picks = rng.integers(0, len(keys), size=len(keys))
        rows.extend(groups[keys[i]] for i in picks)
    return np.concatenate(rows) if rows else np.array([], dtype=int)


def group_bootstrap(df: pd.DataFrame, metric: Callable[[pd.DataFrame], Optional[float]], group_col: str = "capture_id",
                    strata_col: str = "y", n_boot: int = 1000, seed: int = 42, ci: float = 0.95) -> Dict:
    df = df.reset_index(drop=True)
    counts = {int(k): int(v) for k, v in df.groupby(strata_col)[group_col].nunique().items()}
    point = metric(df)
    status = _status(counts) if len(counts) == 2 else "INSUFFICIENT_GROUPS"
    out = {"estimate": point, "groups_per_stratum": counts, "status": status, "n_boot": n_boot,
           "resampling_unit": group_col, "ci_low": None, "ci_high": None}
    if status == "INSUFFICIENT_GROUPS" or point is None:
        return out
    strata = _group_index(df, group_col, strata_col)
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(n_boot):
        v = metric(df.iloc[_resample(strata, rng)])
        if v is not None and np.isfinite(v):
            vals.append(v)
    if len(vals) < n_boot * 0.9:
        out["status"] = "UNSTABLE"
        out["valid_replicates"] = len(vals)
        return out
    a = (1 - ci) / 2
    out["ci_low"], out["ci_high"] = float(np.quantile(vals, a)), float(np.quantile(vals, 1 - a))
    out["valid_replicates"] = len(vals)
    return out


def paired_group_bootstrap(df: pd.DataFrame, metric: Callable[[np.ndarray, np.ndarray], Optional[float]],
                           score_a: str, score_b: str, group_col: str = "capture_id", strata_col: str = "y",
                           n_boot: int = 1000, seed: int = 42, ci: float = 0.95) -> Dict:
    """`df` has one row per flow with y, both systems' scores and the group column."""
    df = df.reset_index(drop=True)
    y = df["y"].to_numpy()
    counts = {int(k): int(v) for k, v in df.groupby(strata_col)[group_col].nunique().items()}
    a0, b0 = metric(y, df[score_a].to_numpy()), metric(y, df[score_b].to_numpy())
    out = {"metric_a": a0, "metric_b": b0, "difference": (b0 - a0) if (a0 is not None and b0 is not None) else None,
           "groups_per_stratum": counts, "status": _status(counts) if len(counts) == 2 else "INSUFFICIENT_GROUPS",
           "ci_low": None, "ci_high": None, "p_value_bootstrap": None, "n_boot": n_boot, "resampling_unit": group_col}
    if out["status"] == "INSUFFICIENT_GROUPS" or out["difference"] is None:
        return out
    strata = _group_index(df, group_col, strata_col)
    rng = np.random.default_rng(seed)
    sa, sb = df[score_a].to_numpy(), df[score_b].to_numpy()
    diffs = []
    for _ in range(n_boot):
        r = _resample(strata, rng)
        ma, mb = metric(y[r], sa[r]), metric(y[r], sb[r])
        if ma is not None and mb is not None:
            diffs.append(mb - ma)
    diffs = np.array(diffs)
    if diffs.size < n_boot * 0.9:
        out["status"] = "UNSTABLE"
        return out
    a = (1 - ci) / 2
    out["ci_low"], out["ci_high"] = float(np.quantile(diffs, a)), float(np.quantile(diffs, 1 - a))
    out["p_value_bootstrap"] = float(min(1.0, 2 * min((diffs <= 0).mean(), (diffs >= 0).mean())))
    return out


def holm(pvalues: Dict[str, Optional[float]], alpha: float = 0.05) -> Dict[str, Dict]:
    items = [(k, p) for k, p in pvalues.items() if p is not None]
    items.sort(key=lambda kv: kv[1])
    m = len(items)
    out: Dict[str, Dict] = {k: {"p": None, "p_holm": None, "reject": None} for k in pvalues}
    running = 0.0
    for i, (k, p) in enumerate(items):
        adj = min(1.0, (m - i) * p)
        running = max(running, adj)
        out[k] = {"p": p, "p_holm": running, "reject": running <= alpha}
    return out
