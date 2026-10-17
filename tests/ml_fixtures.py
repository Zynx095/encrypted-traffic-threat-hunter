"""
Synthetic TEST FIXTURES for Phase 8-10 unit tests.

Everything here is generated from a seeded random number generator to exercise code paths.
None of it is research data, and nothing produced from it is ever written to the experiment
registry or reported as a result.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd

from ml.features.governance import FLOW_FEATURES, TLS_STRUCTURAL_NUMERIC, schema_fingerprint, track_columns


def synthetic_corpus(captures_per_class: int = 6, flows_per_capture: int = 40, seed: int = 0,
                     fingerprint_rate: float = 0.6) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    idx = 0
    for y in (0, 1):
        for c in range(captures_per_class):
            cap = f"{'MAL' if y else 'BEN'}-C{c:02d}"
            ds = "SYN-MAL" if y else "SYN-BEN"
            fam = f"FAM{c % 3}" if y else "BENIGN"
            for i in range(flows_per_capture):
                r = {f: float(rng.normal(loc=(0.8 if y else 0.0), scale=1.0)) for f in FLOW_FEATURES}
                if rng.random() < 0.1:
                    r["iat_std"] = np.nan          # undefined for some flows
                has_fp = rng.random() < fingerprint_rate
                r.update({
                    "clienthello_present": bool(has_fp), "serverhello_present": bool(has_fp), "sni_present": bool(has_fp),
                    "tls_version": (1.3 if rng.random() < 0.5 else 1.2) if has_fp else np.nan,
                    "alpn_value": ("h2" if rng.random() < 0.5 else None) if has_fp else None,
                    "ja3_hash": (f"ja3_{y}_{rng.integers(0, 4)}" if has_fp else None),
                    "ja4": (f"t13d_{y}_{rng.integers(0, 4)}" if has_fp else None),
                    "corpus_index": idx, "label": "MALICIOUS" if y else "BENIGN", "y": y, "capture_id": cap,
                    "dataset_id": ds, "family_group": fam, "collection_date": f"{2017 + y}-05-01",
                })
                r["behavioral_hash"] = hashlib.sha256(f"{cap}-{i // 2}".encode()).hexdigest()   # pairs of duplicates
                rows.append(r)
                idx += 1
    return pd.DataFrame(rows)


def complete_flow_record(**overrides) -> Dict:
    """A flow record that carries every input column of tracks A-E (synthetic values)."""
    rec = {f: 1.0 for f in FLOW_FEATURES}
    rec.update({"clienthello_present": True, "serverhello_present": True, "sni_present": True,
                "tls_version": 1.3, "alpn_value": "h2", "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
                "ja4": "t13d151600_8daaf6152771_e8006e86689d", "flow_id": "fixture_flow",
                "ja4_implementation": "ETTH_JA4_V1", "ja4_version": "etth_ja4_v1"})
    rec.update(overrides)
    return rec


def fixture_models(tmp_dir: Path, tracks: List[str] = None, seed: int = 0):
    """Train tiny logistic models per track on synthetic data, export them safely and reload them."""
    from ml.estimators.artifact import SafeTabularModel, export_model
    from ml.estimators.preprocessing import TabularPreprocessor
    from ml.estimators.zoo import MODEL_SPECS
    from ml.benchmark.runner import _matrix
    from ml.features.governance import population_mask
    df = synthetic_corpus(seed=seed)
    out = {}
    for track in tracks or ["A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"]:
        cols = track_columns(track)
        part = df.loc[population_mask(df, track)].reset_index(drop=True)
        X = _matrix(part, cols)
        pre = TabularPreprocessor(numeric=cols["numeric"], categorical=cols["categorical"], scale=True).fit(X)
        clf = MODEL_SPECS["logreg"].build(seed=seed).fit(pre.transform(X), part["y"].to_numpy())
        d = Path(tmp_dir) / track
        hashes = export_model(pre, clf, d, {"fixture": True})
        model = SafeTabularModel.load(d, hashes)
        entry = {"model_id": f"fixture-{track.lower()}", "version": 1, "track": track, "estimator": "logreg",
                 "research_status": "TEST_FIXTURE", "calibration": {"status": "UNCALIBRATED"},
                 "thresholds": {"fpr<=0.01": 0.5}, "feature_schema": {"fingerprint": schema_fingerprint(track)},
                 "ood_reference": {"numeric_quantiles": {"flow_duration": {"q005": -3.0, "q995": 4.0}}},
                 "known_vocab": {c: pre.state_["categorical"][c].get("vocab") for c in cols["categorical"]},
                 "training": {"captures": sorted(part["capture_id"].unique())}}
        out[track] = (entry, model)
    return out
