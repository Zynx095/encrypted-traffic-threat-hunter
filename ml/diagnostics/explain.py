"""
Held-out explanations for benchmark models.

* Permutation importance is computed on OUTER TEST folds (never on training data) by permuting
  raw input columns and measuring the drop in average precision. It is used for description
  only; no feature selection in this project uses it, so it cannot leak into evaluation.
* Impurity-based importance (tree models) is reported separately and labelled as such; it is
  computed on training data and is biased towards high-cardinality / continuous features.
* Logistic-regression coefficients are reported on standardised inputs.
Importance describes predictive association in this corpus. It is not causal and, on
source-confounded data, high importance can indicate a capture-environment shortcut.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.pipeline import Pipeline

from ml.benchmark.runner import _matrix
from ml.estimators.preprocessing import TabularPreprocessor
from ml.estimators.zoo import MODEL_SPECS
from ml.evaluation.splits import Fold
from ml.features.governance import population_mask, track_columns

MAX_TEST_ROWS = 4000


def _stratified_sample(idx: np.ndarray, y: np.ndarray, n: int, seed: int) -> np.ndarray:
    if len(idx) <= n:
        return idx
    rng = np.random.default_rng(seed)
    out = []
    for cls in (0, 1):
        cidx = idx[y[idx] == cls]
        k = int(round(n * len(cidx) / len(idx)))
        if len(cidx):
            out.append(rng.choice(cidx, size=max(1, min(k, len(cidx))), replace=False))
    return np.sort(np.concatenate(out))


def explain_track(df_all: pd.DataFrame, track: str, model: str, params: Dict[str, Any], folds: List[Fold],
                  seed: int = 42, n_repeats: int = 5) -> Dict[str, Any]:
    cols = track_columns(track)
    df = df_all.loc[population_mask(df_all, track)].reset_index(drop=True)
    X = _matrix(df, cols)
    y = df["y"].to_numpy()
    spec = MODEL_SPECS[model]
    per_fold, impurity = [], []
    for f in folds:
        if len(f.train_idx) == 0 or not f.two_class_test:
            continue
        pipe = Pipeline([("pre", TabularPreprocessor(numeric=cols["numeric"], categorical=cols["categorical"], scale=spec.scale)),
                         ("clf", spec.build(seed=seed, **params))])
        pipe.fit(X.iloc[f.train_idx], y[f.train_idx])
        te = _stratified_sample(f.test_idx, y, MAX_TEST_ROWS, seed)
        if len(np.unique(y[te])) < 2:
            continue
        pi = permutation_importance(pipe, X.iloc[te], y[te], scoring="average_precision", n_repeats=n_repeats,
                                    random_state=seed, n_jobs=1)
        per_fold.append(pd.Series(pi.importances_mean, index=X.columns))
        clf = pipe.named_steps["clf"]
        names = pipe.named_steps["pre"].feature_names_out_
        if hasattr(clf, "feature_importances_"):
            s = pd.Series(clf.feature_importances_, index=names)
            base = s.index.map(lambda n: n.split("=")[0].split("__")[0])
            impurity.append(s.groupby(base).sum())
        elif hasattr(clf, "coef_"):
            impurity.append(pd.Series(clf.coef_[0], index=names))
    if not per_fold:
        return {"status": "NOT_RUN", "reason": "no fold with a two-class test set"}
    perm = pd.concat(per_fold, axis=1)
    out = {
        "status": "COMPLETED", "track": track, "model": model, "params": params, "folds_used": len(per_fold),
        "method": f"permutation importance on outer test folds (<= {MAX_TEST_ROWS} stratified rows/fold, {n_repeats} repeats, AP drop)",
        "permutation_importance": [
            {"feature": k, "mean_ap_drop": float(perm.loc[k].mean()), "sd_across_folds": float(perm.loc[k].std(ddof=1)) if perm.shape[1] > 1 else None}
            for k in perm.mean(axis=1).sort_values(ascending=False).index],
        "caveat": "Association within this corpus only; not causal; may reflect capture-environment shortcuts.",
    }
    if impurity:
        imp = pd.concat(impurity, axis=1).mean(axis=1).sort_values(key=np.abs, ascending=False)
        out["model_internal_importance"] = {
            "kind": "impurity (training data, biased)" if hasattr(clf, "feature_importances_") else "logistic coefficients (standardised inputs)",
            "top": [{"feature": k, "value": float(v)} for k, v in imp.head(25).items()]}
    return out
