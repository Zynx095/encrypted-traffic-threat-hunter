"""Re-verification of persisted experiment records against their out-of-fold predictions (synthetic)."""
import numpy as np
import pandas as pd

import ml.reporting.verify as V
from ml.benchmark.registry import sha256_file
from ml.evaluation import metrics as M


def _record(tmp_path, ap_shift=0.0):
    rng = np.random.default_rng(0)
    y = np.array([0] * 50 + [1] * 50)
    s = np.clip(rng.normal(0.3 + 0.4 * y, 0.2), 0, 1)
    pred = (s >= 0.6).astype(int)
    P = pd.DataFrame({"y": y, "score_calibrated": s, "pred@fpr<=0.01": pred})
    path = tmp_path / "exp" / "predictions.parquet"
    path.parent.mkdir(parents=True)
    P.to_parquet(path)
    neg, pos = P[P.y == 0], P[P.y == 1]
    return {"experiment_id": "EXP-synthetic", "status": "COMPLETED", "config": {"track": "A_FLOW", "model": "logreg"},
            "artifacts": {"predictions.parquet": {"path": "exp/predictions.parquet", "sha256": sha256_file(path)}},
            "metrics": {"pooled_calibrated": {"average_precision": M.ranking_metrics(y, s)["average_precision"] + ap_shift},
                        "at_validation_thresholds": {"pred@fpr<=0.01": {
                            "fpr": float((neg["pred@fpr<=0.01"] == 1).mean()), "recall": float((pos["pred@fpr<=0.01"] == 1).mean()),
                            "n_pos": 50, "n_neg": 50}}}}


def test_matching_record_is_verified(tmp_path, monkeypatch):
    monkeypatch.setattr(V, "ROOT", tmp_path)
    assert V.verify_record(_record(tmp_path))["result"] == "VERIFIED"


def test_altered_metric_is_reported_as_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(V, "ROOT", tmp_path)
    res = V.verify_record(_record(tmp_path, ap_shift=0.01))
    assert res["result"] == "MISMATCH" and res["checks"]["average_precision"]["match"] is False


def test_tampered_or_missing_predictions_are_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(V, "ROOT", tmp_path)
    rec = _record(tmp_path)
    rec["artifacts"]["predictions.parquet"]["sha256"] = "0" * 64
    assert V.verify_record(rec)["result"] == "CHECKSUM_MISMATCH"
    rec["artifacts"]["predictions.parquet"]["path"] = "exp/absent.parquet"
    assert V.verify_record(rec)["result"] == "MISSING"
