"""
Exportable, training-fold-only preprocessing.

All learned state (medians, scaling moments, category vocabularies, frequencies) is fitted in
`fit` on the training fold only and can be serialised to plain JSON, so the exact transform
used in evaluation is reproduced at inference time without pickle.

Missing values:
  * numeric NaN means "not defined for this flow" (e.g. IAT of a single-packet flow). It is
    replaced by the training median AND flagged with a missing-indicator column, so the
    model can distinguish an imputed value from an observed one.
  * a missing fingerprint is a separate explicit level (__MISSING__); fingerprints never
    seen in training (or below min_frequency) map to __UNKNOWN__. Raw fingerprint strings are
    never converted to ordinal numbers.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

MISSING = "__MISSING__"
UNKNOWN = "__UNKNOWN__"
ENCODINGS = ("onehot", "frequency", "hashing")


def _as_category_strings(series: pd.Series) -> pd.Series:
    def norm(v):
        if v is None or (isinstance(v, float) and np.isnan(v)):
            return MISSING
        s = str(v)
        return MISSING if s.strip() == "" or s.lower() in ("nan", "none") else s
    return series.map(norm)


def _stable_bucket(value: str, n_buckets: int) -> int:
    return int(hashlib.md5(value.encode()).hexdigest(), 16) % n_buckets


class TabularPreprocessor(BaseEstimator, TransformerMixin):
    def __init__(self, numeric: Optional[List[str]] = None, categorical: Optional[List[str]] = None,
                 scale: bool = False, encoding: str = "onehot", min_frequency: int = 2,
                 hashing_buckets: int = 64, missing_indicators: bool = True):
        self.numeric = numeric
        self.categorical = categorical
        self.scale = scale
        self.encoding = encoding
        self.min_frequency = min_frequency
        self.hashing_buckets = hashing_buckets
        self.missing_indicators = missing_indicators

    # ------------------------------------------------------------------ fitting --
    def fit(self, X: pd.DataFrame, y=None):
        if self.encoding not in ENCODINGS:
            raise ValueError(f"Unknown encoding {self.encoding}")
        num = list(self.numeric or [])
        cat = list(self.categorical or [])
        missing_cols = [c for c in num + cat if c not in X.columns]
        if missing_cols:
            raise ValueError(f"Input is missing required columns: {missing_cols}")
        self.state_: Dict[str, Any] = {"numeric": {}, "categorical": {}}
        for c in num:
            col = pd.to_numeric(X[c], errors="coerce").astype(float)
            med = float(np.nanmedian(col)) if col.notna().any() else 0.0
            filled = col.fillna(med)
            mean = float(filled.mean()) if self.scale else 0.0
            std = float(filled.std(ddof=0)) if self.scale else 1.0
            self.state_["numeric"][c] = {
                "median": med, "mean": mean, "std": std if std > 0 else 1.0,
                "indicator": bool(self.missing_indicators and col.isna().any()),
                "all_missing_in_training": bool(col.isna().all()),
            }
        for c in cat:
            vals = _as_category_strings(X[c])
            counts = vals[vals != MISSING].value_counts()
            n = max(int((vals != MISSING).sum()), 1)
            if self.encoding == "onehot":
                vocab = sorted(counts[counts >= self.min_frequency].index.tolist())
                self.state_["categorical"][c] = {"vocab": vocab}
            elif self.encoding == "frequency":
                self.state_["categorical"][c] = {"freq": {k: float(v) / n for k, v in counts.items()}}
            else:
                self.state_["categorical"][c] = {"buckets": int(self.hashing_buckets)}
        self.feature_names_out_ = self._names()
        return self

    def _names(self) -> List[str]:
        names: List[str] = []
        for c, s in self.state_["numeric"].items():
            names.append(c)
            if s["indicator"]:
                names.append(f"{c}__is_missing")
        for c, s in self.state_["categorical"].items():
            if self.encoding == "onehot":
                names += [f"{c}={v}" for v in s["vocab"]] + [f"{c}={UNKNOWN}", f"{c}={MISSING}"]
            elif self.encoding == "frequency":
                names += [f"{c}__train_frequency", f"{c}__is_unknown", f"{c}__is_missing"]
            else:
                names += [f"{c}__bucket{i}" for i in range(s["buckets"])] + [f"{c}__is_missing"]
        return names

    # --------------------------------------------------------------- transform --
    def transform(self, X: pd.DataFrame) -> np.ndarray:
        return transform_with_state(self.state_, self.encoding, X)

    def get_feature_names_out(self, input_features=None):
        return np.array(self.feature_names_out_)

    # ------------------------------------------------------------ serialisation --
    def to_dict(self) -> Dict[str, Any]:
        return {"encoding": self.encoding, "scale": self.scale, "min_frequency": self.min_frequency,
                "hashing_buckets": self.hashing_buckets, "missing_indicators": self.missing_indicators,
                "state": self.state_, "feature_names_out": self.feature_names_out_}


def transform_with_state(state: Dict[str, Any], encoding: str, X: pd.DataFrame) -> np.ndarray:
    blocks: List[np.ndarray] = []
    n = len(X)
    for c, s in state["numeric"].items():
        if c not in X.columns:
            raise ValueError(f"Input is missing required numeric column '{c}'")
        col = pd.to_numeric(X[c], errors="coerce").astype(float).to_numpy()
        miss = np.isnan(col)
        vals = np.where(miss, s["median"], col)
        vals = (vals - s["mean"]) / s["std"]
        blocks.append(vals.reshape(-1, 1))
        if s["indicator"]:
            blocks.append(miss.astype(float).reshape(-1, 1))
    for c, s in state["categorical"].items():
        if c not in X.columns:
            raise ValueError(f"Input is missing required categorical column '{c}'")
        vals = _as_category_strings(X[c]).to_numpy()
        is_missing = vals == MISSING
        if encoding == "onehot":
            vocab = s["vocab"]
            index = {v: i for i, v in enumerate(vocab)}
            out = np.zeros((n, len(vocab) + 2))
            for r, v in enumerate(vals):
                if v == MISSING:
                    out[r, len(vocab) + 1] = 1.0
                elif v in index:
                    out[r, index[v]] = 1.0
                else:
                    out[r, len(vocab)] = 1.0
            blocks.append(out)
        elif encoding == "frequency":
            freq = s["freq"]
            f = np.array([0.0 if v == MISSING else freq.get(v, 0.0) for v in vals])
            unk = np.array([0.0 if v == MISSING else float(v not in freq) for v in vals])
            blocks.append(np.column_stack([f, unk, is_missing.astype(float)]))
        else:
            b = s["buckets"]
            out = np.zeros((n, b + 1))
            for r, v in enumerate(vals):
                if v == MISSING:
                    out[r, b] = 1.0
                else:
                    out[r, _stable_bucket(v, b)] = 1.0
            blocks.append(out)
    if not blocks:
        return np.zeros((n, 0))
    return np.hstack(blocks)
