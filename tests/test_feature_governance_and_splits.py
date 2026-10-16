"""Phase 9: feature governance, leakage guard, split invariants and train-only preprocessing."""
import numpy as np
import pandas as pd
import pytest

from ml.estimators.preprocessing import MISSING, UNKNOWN, TabularPreprocessor
from ml.evaluation.splits import InfeasibleSplit, capture_fold_assignment, make_folds, validate_fold
from ml.features.governance import (CANONICAL_TRACKS, FORBIDDEN, LeakageError, assert_model_safe, population_mask,
                                    schema_fingerprint, track_columns)
from tests.ml_fixtures import synthetic_corpus


# --------------------------------------------------------------- governance --
@pytest.mark.parametrize("col", ["dataset_id", "capture_id", "source_file", "flow_id", "behavioral_hash", "label",
                                 "forward_endpoint", "collection_date", "family_group", "corpus_index"])
def test_provenance_columns_cannot_enter_model_matrix(col):
    with pytest.raises(LeakageError):
        assert_model_safe(["flow_duration", col])


def test_unregistered_and_sequence_columns_rejected():
    with pytest.raises(LeakageError, match="not in feature registry"):
        assert_model_safe(["src_ip_octet"])
    with pytest.raises(LeakageError):
        assert_model_safe(["sequence_packet_lengths"])
    with pytest.raises(LeakageError):
        assert_model_safe(["ja3s_hash"])


def test_all_five_tracks_keep_their_meaning():
    a, b, c, d, e = (track_columns(t) for t in CANONICAL_TRACKS)
    assert b == {"numeric": [], "categorical": ["ja3_hash"]}
    assert c == {"numeric": [], "categorical": ["ja4"]}
    assert "ja3_hash" not in a["categorical"] and "ja4" not in a["categorical"]
    assert d["numeric"] == a["numeric"] and set(d["categorical"]) - set(a["categorical"]) == {"ja3_hash"}
    assert e["numeric"] == a["numeric"] and set(e["categorical"]) - set(a["categorical"]) == {"ja4"}
    assert "ja4" not in d["categorical"] and "ja3_hash" not in e["categorical"]
    for t in CANONICAL_TRACKS:
        cols = track_columns(t)
        assert not set(cols["numeric"] + cols["categorical"]) & set(FORBIDDEN)


def test_schema_fingerprint_stable_and_distinct():
    assert schema_fingerprint("A_FLOW") == schema_fingerprint("A_FLOW")
    assert len({schema_fingerprint(t) for t in CANONICAL_TRACKS}) == 5


def test_fingerprint_population_masks_drop_missing_explicitly():
    df = synthetic_corpus()
    assert population_mask(df, "A_FLOW").all()
    m = population_mask(df, "D_JA3_FLOW")
    assert df.loc[m, "ja3_hash"].notna().all() and df.loc[~m, "ja3_hash"].isna().all()


# ------------------------------------------------------------ preprocessing --
def test_preprocessing_learns_only_from_training_rows():
    train = pd.DataFrame({"x": [1.0, 2.0, np.nan], "fp": ["a", "a", None]})
    test = pd.DataFrame({"x": [np.nan, 1000.0], "fp": ["zzz", None]})
    pre = TabularPreprocessor(numeric=["x"], categorical=["fp"], scale=False, min_frequency=1).fit(train)
    assert pre.state_["numeric"]["x"]["median"] == 1.5
    Z = pre.transform(test)
    names = list(pre.feature_names_out_)
    assert Z[0, names.index("x")] == 1.5 and Z[0, names.index("x__is_missing")] == 1.0
    assert Z[0, names.index(f"fp={UNKNOWN}")] == 1.0          # unseen fingerprint -> explicit UNKNOWN
    assert Z[1, names.index(f"fp={MISSING}")] == 1.0          # missing fingerprint -> explicit MISSING
    pre2 = TabularPreprocessor(numeric=["x"], categorical=["fp"]).fit(pd.concat([train, test]))
    assert pre2.state_["numeric"]["x"]["median"] != pre.state_["numeric"]["x"]["median"]


def test_fingerprints_are_never_ordinal_encoded():
    df = pd.DataFrame({"fp": ["b", "a", "c", "a"]})
    for enc in ("onehot", "frequency", "hashing"):
        pre = TabularPreprocessor(categorical=["fp"], encoding=enc, min_frequency=1).fit(df)
        Z = pre.transform(df)
        assert set(np.unique(Z[:, :3 if enc == "frequency" else Z.shape[1]]).round(6)) <= set(np.round([0, 1, 0.25, 0.5], 6))


def test_missing_required_column_rejected():
    pre = TabularPreprocessor(numeric=["x"], categorical=[]).fit(pd.DataFrame({"x": [1.0, 2.0]}))
    with pytest.raises(ValueError, match="missing required numeric column"):
        pre.transform(pd.DataFrame({"y": [1.0]}))


# ------------------------------------------------------------------- splits --
def test_capture_folds_hold_out_whole_captures_and_purge_duplicates():
    df = synthetic_corpus()
    # create one cross-capture duplicate group
    df.loc[df["capture_id"] == "BEN-C01", "behavioral_hash"] = df.loc[df["capture_id"] == "BEN-C00", "behavioral_hash"].iloc[0]
    folds = make_folds(df, "CAPTURE_GROUP_KFOLD", seed=1)
    for f in folds:
        tr, te = df.iloc[f.train_idx], df.iloc[f.test_idx]
        assert not set(tr["capture_id"]) & set(te["capture_id"])
        assert not set(tr["behavioral_hash"]) & set(te["behavioral_hash"])
        assert f.two_class_test
    assert sum(f.purged_train_rows for f in folds) > 0


def test_behavioral_protocols_never_split_groups():
    df = synthetic_corpus()
    for protocol in ("BEHAVIORAL_HOLDOUT", "BEHAVIORAL_GROUP_KFOLD"):
        for f in make_folds(df, protocol, seed=3):
            validate_fold(df, f)


def test_validate_fold_detects_leakage():
    df = synthetic_corpus()
    folds = make_folds(df, "BEHAVIORAL_HOLDOUT", seed=0)
    f = folds[0]
    f.train_idx = np.append(f.train_idx, f.test_idx[:1])
    with pytest.raises(AssertionError):
        validate_fold(df, f)


def test_leave_one_source_out_marks_single_class_training_infeasible():
    df = synthetic_corpus()
    folds = make_folds(df, "LEAVE_ONE_SOURCE_OUT")
    assert all(len(f.train_idx) == 0 and f.held_out.get("infeasible") for f in folds)


def test_family_holdout_and_temporal_infeasibility():
    df = synthetic_corpus()
    folds = make_folds(df, "LEAVE_ONE_FAMILY_OUT")
    for f in folds:
        fam = f.held_out["family_group"]
        tr = df.iloc[f.train_idx]
        assert fam not in set(tr.loc[tr["y"] == 1, "family_group"])
    with pytest.raises(InfeasibleSplit):
        make_folds(df, "TEMPORAL_HOLDOUT", cutoff_year=2017)


def test_capture_assignment_requires_two_captures_per_class():
    caps = pd.DataFrame({"capture_id": ["a", "b", "c"], "y": [0, 1, 1]})
    with pytest.raises(InfeasibleSplit):
        capture_fold_assignment(caps, 5, 0)


def test_phase7_resampling_pipeline_resamples_training_only():
    from imblearn.over_sampling import RandomOverSampler
    from sklearn.linear_model import LogisticRegression
    from pipeline.preprocessing import get_full_pipeline
    X = pd.DataFrame({"a": np.arange(20, dtype=float)})
    y = pd.Series([0] * 16 + [1] * 4)
    pipe = get_full_pipeline(["a"], [], LogisticRegression(), resampler=RandomOverSampler(random_state=0))
    pipe.fit(X, y)
    assert len(pipe.predict(X.iloc[:7])) == 7            # no resampling at prediction time
