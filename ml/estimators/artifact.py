"""
Safe model artefact format "etth-tabular-model/1".

An artefact is a directory with two files and no executable content:
    model.json   -- metadata, preprocessing state (JSON), estimator type and small parameters
    arrays.npz   -- numeric arrays (coefficients or tree node tables), loaded with
                    numpy.load(allow_pickle=False)

Supported estimators: LogisticRegression, RandomForestClassifier, ExtraTreesClassifier.
pickle/joblib are never used, so loading an artefact cannot execute code. Both files are
SHA-256 pinned in the model registry and re-verified before every load.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from ml.estimators.preprocessing import TabularPreprocessor, transform_with_state

FORMAT = "etth-tabular-model/1"


class ArtifactError(ValueError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def export_model(pre: TabularPreprocessor, clf: Any, out_dir: Path, metadata: Dict[str, Any],
                 calibration: Optional[Dict[str, float]] = None) -> Dict[str, str]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    arrays: Dict[str, np.ndarray] = {}
    if isinstance(clf, LogisticRegression):
        est = {"type": "logistic_regression", "classes": [int(c) for c in clf.classes_]}
        arrays["coef"] = clf.coef_.astype(np.float64)
        arrays["intercept"] = clf.intercept_.astype(np.float64)
    elif isinstance(clf, (RandomForestClassifier, ExtraTreesClassifier)):
        if list(clf.classes_) != [0, 1]:
            raise ArtifactError(f"Expected binary classes [0, 1], got {list(clf.classes_)}")
        est = {"type": "tree_ensemble", "n_trees": len(clf.estimators_), "classes": [0, 1]}
        offsets = [0]
        lefts, rights, feats, thrs, probs = [], [], [], [], []
        for tree in clf.estimators_:
            t = tree.tree_
            value = t.value[:, 0, :].astype(np.float64)
            p1 = value[:, 1] / np.clip(value.sum(axis=1), 1e-300, None)
            lefts.append(t.children_left.astype(np.int64))
            rights.append(t.children_right.astype(np.int64))
            feats.append(t.feature.astype(np.int64))
            thrs.append(t.threshold.astype(np.float64))
            probs.append(p1)
            offsets.append(offsets[-1] + t.node_count)
        arrays.update(children_left=np.concatenate(lefts), children_right=np.concatenate(rights),
                      feature=np.concatenate(feats), threshold=np.concatenate(thrs), prob1=np.concatenate(probs),
                      offsets=np.array(offsets, dtype=np.int64))
    else:
        raise ArtifactError(f"Estimator {type(clf).__name__} is not supported by {FORMAT}")

    model = {"format": FORMAT, "estimator": est, "preprocessing": pre.to_dict(), "metadata": metadata,
             "calibration": calibration}
    np.savez_compressed(out_dir / "arrays.npz", **arrays)
    (out_dir / "model.json").write_text(json.dumps(model, indent=2, default=str), encoding="utf-8")
    return {"model.json": _sha256(out_dir / "model.json"), "arrays.npz": _sha256(out_dir / "arrays.npz")}


class SafeTabularModel:
    def __init__(self, model: Dict[str, Any], arrays: Dict[str, np.ndarray]):
        self.model = model
        self.arrays = arrays
        self.metadata = model.get("metadata", {})
        self.preprocessing = model["preprocessing"]
        self.calibration = model.get("calibration")
        self.required_numeric: List[str] = list(self.preprocessing["state"]["numeric"].keys())
        self.required_categorical: List[str] = list(self.preprocessing["state"]["categorical"].keys())

    @classmethod
    def load(cls, directory: Path, expected_sha256: Optional[Dict[str, str]] = None) -> "SafeTabularModel":
        directory = Path(directory)
        mj, an = directory / "model.json", directory / "arrays.npz"
        if not mj.exists() or not an.exists():
            raise ArtifactError(f"Incomplete artefact at {directory}")
        if expected_sha256:
            for name, path in (("model.json", mj), ("arrays.npz", an)):
                actual = _sha256(path)
                if expected_sha256.get(name) != actual:
                    raise ArtifactError(f"Checksum mismatch for {name}: expected {expected_sha256.get(name)}, got {actual}")
        model = json.loads(mj.read_text(encoding="utf-8"))
        if model.get("format") != FORMAT:
            raise ArtifactError(f"Unsupported artefact format {model.get('format')}")
        with np.load(an, allow_pickle=False) as data:
            arrays = {k: data[k] for k in data.files}
        return cls(model, arrays)

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        return transform_with_state(self.preprocessing["state"], self.preprocessing["encoding"], X)

    def raw_scores(self, X: pd.DataFrame) -> np.ndarray:
        Z = self.transform(X)
        est = self.model["estimator"]
        if est["type"] == "logistic_regression":
            logit = Z @ self.arrays["coef"][0] + self.arrays["intercept"][0]
            return 1.0 / (1.0 + np.exp(-logit))
        return self._forest_proba(Z)

    def predict_proba1(self, X: pd.DataFrame) -> np.ndarray:
        """Model score for the MALICIOUS class; calibrated if a validation-fitted calibrator is stored."""
        s = self.raw_scores(X)
        if self.calibration:
            z = self.calibration["a"] * s + self.calibration["b"]
            s = 1.0 / (1.0 + np.exp(-z))
        return s

    def _forest_proba(self, Z: np.ndarray, chunk: int = 2048) -> np.ndarray:
        """All trees advanced simultaneously (rows x trees), in row chunks; one iteration per tree level."""
        # sklearn trees compare float32-cast inputs against float64 thresholds.
        Zc = Z.astype(np.float32).astype(np.float64)
        a = self.arrays
        roots = a["offsets"][:-1]                      # global index of each tree's root
        left, right, feat, thr, prob = a["children_left"], a["children_right"], a["feature"], a["threshold"], a["prob1"]
        base = roots[None, :]
        out = np.empty(Zc.shape[0])
        for s0 in range(0, Zc.shape[0], chunk):
            Zb = Zc[s0:s0 + chunk]
            n = Zb.shape[0]
            local = np.zeros((n, roots.size), dtype=np.int64)       # node index local to each tree
            rows = np.arange(n)[:, None]
            while True:
                g = base + local
                lc = left[g]
                active = lc != -1
                if not active.any():
                    break
                f = np.where(active, feat[g], 0)
                go_left = Zb[rows, f] <= thr[g]
                nxt = np.where(go_left, lc, right[g])
                local = np.where(active, nxt, local)
            out[s0:s0 + n] = prob[base + local].mean(axis=1)
        return out
