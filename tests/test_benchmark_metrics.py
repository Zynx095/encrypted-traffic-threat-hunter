"""Phase 9: metric conventions, group-aware uncertainty, runner invariants, registry immutability."""
import json

import numpy as np
import pandas as pd
import pytest

import ml.benchmark.registry as R
from ml.evaluation import metrics as M
from ml.evaluation.uncertainty import group_bootstrap, holm, paired_group_bootstrap
from tests.ml_fixtures import synthetic_corpus


@pytest.fixture()
def scratch_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "PHASE9_ROOT", tmp_path / "phase9")
    monkeypatch.setattr(R, "REGISTRY_INDEX", tmp_path / "index.jsonl")
    return tmp_path


# ------------------------------------------------------------------ metrics --
def test_average_precision_and_trapezoid_are_reported_separately():
    y = np.array([0, 1, 0, 1, 1, 0, 0, 1])
    s = np.array([0.1, 0.9, 0.35, 0.4, 0.8, 0.7, 0.2, 0.6])
    m = M.ranking_metrics(y, s)
    assert m["n"] == 8 and m["n_pos"] == 4 and m["n_neg"] == 4
    assert m["average_precision"] != pytest.approx(m["pr_auc_trapezoid"])
    assert 0 <= m["ece_15bin"] <= 1


def test_single_class_metrics_are_undefined_not_perfect():
    m = M.ranking_metrics(np.ones(5, dtype=int), np.linspace(0, 1, 5))
    assert m["average_precision"] is None and m["roc_auc"] is None and "undefined_reason" in m
    t = M.threshold_metrics(np.ones(5, dtype=int), np.linspace(0, 1, 5), 0.5)
    assert t["fpr"] is None and t["f1"] is None and t["recall"] == pytest.approx(0.6)


def test_threshold_for_fpr_respects_validation_target():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(1000, int), np.ones(100, int)]
    s = np.r_[rng.random(1000), rng.random(100) + 0.5]
    for target in (0.001, 0.01, 0.05):
        thr = M.threshold_for_fpr(y, s, target)
        assert ((s[y == 0] >= thr).mean()) <= target
    assert M.threshold_for_fpr(np.ones(3, int), np.ones(3), 0.01) is None


def test_ece_known_value():
    y = np.array([1, 0, 1, 0])
    s = np.array([0.9, 0.9, 0.1, 0.1])
    assert M.ece(y, s) == pytest.approx(0.4)


def test_platt_calibration_requires_two_classes():
    assert M.platt_fit(np.ones(4, int), np.ones(4)) is None
    cal = M.platt_fit(np.array([0, 0, 1, 1]), np.array([0.1, 0.2, 0.8, 0.9]))
    assert M.platt_apply(cal, np.array([0.9]))[0] > M.platt_apply(cal, np.array([0.1]))[0]


# -------------------------------------------------------------- uncertainty --
def _pred_frame(n_groups_per_class, rows=20, seed=0):
    rng = np.random.default_rng(seed)
    out = []
    for y in (0, 1):
        for g in range(n_groups_per_class):
            out.append(pd.DataFrame({"y": y, "capture_id": f"{y}-{g}", "score_calibrated": rng.random(rows) * 0.5 + 0.4 * y,
                                     "a": rng.random(rows), "b": rng.random(rows) + 0.3 * y}))
    return pd.concat(out, ignore_index=True)


def _ap(df):
    return M.ranking_metrics(df["y"].to_numpy(), df["score_calibrated"].to_numpy())["average_precision"]


def test_bootstrap_withholds_interval_with_too_few_groups():
    r = group_bootstrap(_pred_frame(3), _ap, n_boot=50)
    assert r["status"] == "INSUFFICIENT_GROUPS" and r["ci_low"] is None and r["estimate"] is not None


def test_bootstrap_resamples_groups_and_flags_few_groups():
    r = group_bootstrap(_pred_frame(6), _ap, n_boot=200)
    assert r["status"] == "FEW_GROUPS" and r["ci_low"] <= r["estimate"] <= r["ci_high"]
    r = group_bootstrap(_pred_frame(12), _ap, n_boot=100)
    assert r["status"] == "OK" and r["groups_per_stratum"] == {0: 12, 1: 12}


def test_paired_bootstrap_zero_difference_for_identical_systems():
    df = _pred_frame(8)
    f = lambda y, s: M.ranking_metrics(y, s)["average_precision"]
    r = paired_group_bootstrap(df, f, "a", "a", n_boot=100)
    assert r["difference"] == 0 and r["ci_low"] == 0 and r["ci_high"] == 0
    r2 = paired_group_bootstrap(df, f, "a", "b", n_boot=200)
    assert r2["difference"] > 0 and r2["p_value_bootstrap"] is not None


def test_holm_adjustment_known_values():
    out = holm({"c1": 0.01, "c2": 0.04, "c3": 0.03, "c4": None})
    assert out["c1"]["p_holm"] == pytest.approx(0.03)
    assert out["c3"]["p_holm"] == pytest.approx(0.06)
    assert out["c2"]["p_holm"] == pytest.approx(0.06)
    assert out["c4"]["p_holm"] is None and out["c1"]["reject"] and not out["c2"]["reject"]


# ------------------------------------------------------------------- runner --
def test_runner_never_uses_test_labels_for_selection_or_thresholds(scratch_registry):
    from ml.benchmark.runner import run_configuration
    from ml.evaluation.splits import capture_fold_assignment
    df = synthetic_corpus(captures_per_class=6, flows_per_capture=30)
    assign = capture_fold_assignment(df[["capture_id", "y"]].drop_duplicates(), 3, 0)
    suite = R.Suite("unit", {"t": 1}, root=R.PHASE9_ROOT)
    rec_a = run_configuration(suite, df, "A_FLOW", "CAPTURE_GROUP_KFOLD", "logreg", capture_assignment=assign, n_boot=50)
    assert rec_a["status"] == "COMPLETED"
    folds_a = json.loads((suite.dir / rec_a["experiment_id"] / "folds.json").read_text())
    # Corrupt the labels of fold-0 test captures only: selection/thresholds of fold 0 must not change.
    test_caps = set(folds_a[0]["held_out"]["captures"])
    df2 = df.copy()
    mask = df2["capture_id"].isin(test_caps)
    rng = np.random.default_rng(1)
    df2.loc[mask, "y"] = rng.permutation(df2.loc[mask, "y"].to_numpy())
    rec_b = run_configuration(suite, df2, "A_FLOW", "CAPTURE_GROUP_KFOLD", "logreg", capture_assignment=assign, n_boot=50)
    folds_b = json.loads((suite.dir / rec_b["experiment_id"] / "folds.json").read_text())
    assert folds_a[0]["selected_params"] == folds_b[0]["selected_params"]
    assert folds_a[0]["thresholds"] == folds_b[0]["thresholds"]
    assert folds_a[0]["calibration"] == folds_b[0]["calibration"]


def test_runner_records_infeasible_and_failed_experiments(scratch_registry):
    from ml.benchmark.runner import run_configuration
    df = synthetic_corpus()
    suite = R.Suite("unit2", {"t": 2}, root=R.PHASE9_ROOT)
    single = df[df["y"] == 1].reset_index(drop=True)
    rec = run_configuration(suite, single, "A_FLOW", "CAPTURE_GROUP_KFOLD", "logreg", n_boot=50)
    assert rec["status"] == "INFEASIBLE"
    broken = df.drop(columns=["flow_duration"])
    rec = run_configuration(suite, broken, "A_FLOW", "CAPTURE_GROUP_KFOLD", "logreg", n_boot=50)
    assert rec["status"] == "FAILED" and "flow_duration" in rec["error"]


def test_experiment_directories_are_never_reused(scratch_registry):
    suite = R.Suite("unit3", {"t": 3}, root=R.PHASE9_ROOT)
    e1, e2 = R.Experiment(suite, {"a": 1}), R.Experiment(suite, {"a": 1})
    assert e1.experiment_id != e2.experiment_id and e1.dir != e2.dir
    e1.finish("COMPLETED", metrics={"x": 1})
    lines = (scratch_registry / "index.jsonl").read_text().splitlines()
    assert any('"experiment_finished"' in ln for ln in lines)
    assert suite.completed_hashes() == {R.config_hash({"a": 1}): e1.experiment_id}


def test_all_five_tracks_run_end_to_end(scratch_registry):
    from ml.benchmark.runner import run_configuration
    from ml.evaluation.splits import capture_fold_assignment
    df = synthetic_corpus(captures_per_class=5, flows_per_capture=24)
    assign = capture_fold_assignment(df[["capture_id", "y"]].drop_duplicates(), 3, 0)
    suite = R.Suite("unit4", {"t": 4}, root=R.PHASE9_ROOT)
    for track in ("A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"):
        rec = run_configuration(suite, df, track, "CAPTURE_GROUP_KFOLD", "logreg", capture_assignment=assign, n_boot=30)
        assert rec["status"] == "COMPLETED", rec.get("error")
        assert rec["coverage"]["population_rows"] <= len(df)
        assert rec["metrics"]["pooled_calibrated"]["n"] == rec["coverage"]["population_rows"]


def test_unseen_fingerprint_analysis_partitions_predictions(scratch_registry):
    from ml.benchmark.runner import run_configuration
    from ml.diagnostics.unseen import unseen_analysis
    from ml.evaluation.splits import capture_fold_assignment
    df = synthetic_corpus(captures_per_class=5, flows_per_capture=24)
    assign = capture_fold_assignment(df[["capture_id", "y"]].drop_duplicates(), 3, 0)
    suite = R.Suite("unit5", {"t": 5}, root=R.PHASE9_ROOT)
    rec = run_configuration(suite, df, "C_JA4", "CAPTURE_GROUP_KFOLD", "logreg", capture_assignment=assign, n_boot=30)
    out = unseen_analysis(df, rec, {"config": {"protocol": "CAPTURE_GROUP_KFOLD", "seed": 42}, "capture_fold_assignment": assign})
    assert out["status"] == "COMPLETED"
    assert sum(c["flows"] for c in out["cells"]) == rec["coverage"]["population_rows"]
    assert unseen_analysis(df, {**rec, "config": {**rec["config"], "track": "A_FLOW"}}, {})["status"] == "NOT_APPLICABLE"
