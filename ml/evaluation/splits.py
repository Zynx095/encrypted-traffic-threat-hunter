"""
Split protocols with explicit feasibility checks.

Invariant enforced for every protocol: no behavioral_hash group appears in both the training
and the test side of a fold. For capture-level protocols, whole capture sessions are held
out and any TRAINING row whose behavioral_hash also occurs in the test fold is purged from
training (the test population is never altered). Purge counts are reported per fold.

Protocols:
  BEHAVIORAL_HOLDOUT       legacy Phase 7 protocol: GroupShuffleSplit on behavioral_hash
  BEHAVIORAL_GROUP_KFOLD   StratifiedGroupKFold on behavioral_hash
  CAPTURE_GROUP_KFOLD      StratifiedGroupKFold on capture_id (whole sessions held out)
  LEAVE_ONE_SOURCE_OUT     each dataset held out in turn (single-class test folds allowed)
  LEAVE_ONE_FAMILY_OUT     each malware family group held out, benign captures rotated
  TEMPORAL_HOLDOUT         captures collected after a cutoff year are held out
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold

PROTOCOLS = ("BEHAVIORAL_HOLDOUT", "BEHAVIORAL_GROUP_KFOLD", "CAPTURE_GROUP_KFOLD", "LEAVE_ONE_SOURCE_OUT",
             "LEAVE_ONE_FAMILY_OUT", "TEMPORAL_HOLDOUT")


class InfeasibleSplit(ValueError):
    pass


@dataclass
class Fold:
    name: str
    train_idx: np.ndarray
    test_idx: np.ndarray
    test_classes: List[int]
    purged_train_rows: int = 0
    held_out: Dict[str, Any] = field(default_factory=dict)

    @property
    def two_class_test(self) -> bool:
        return len(self.test_classes) == 2

    def summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        tr, te = df.iloc[self.train_idx], df.iloc[self.test_idx]
        return {"name": self.name, "train_rows": int(len(tr)), "test_rows": int(len(te)),
                "train_pos": int(tr["y"].sum()), "train_neg": int((tr["y"] == 0).sum()),
                "test_pos": int(te["y"].sum()), "test_neg": int((te["y"] == 0).sum()),
                "train_captures": int(tr["capture_id"].nunique()), "test_captures": int(te["capture_id"].nunique()),
                "purged_train_rows": int(self.purged_train_rows), "held_out": self.held_out}


def _purge(df: pd.DataFrame, train_idx: np.ndarray, test_idx: np.ndarray):
    test_groups = set(df["behavioral_hash"].iloc[test_idx])
    keep = ~df["behavioral_hash"].iloc[train_idx].isin(test_groups).to_numpy()
    return train_idx[keep], int((~keep).sum())


def _make_fold(df, name, train_idx, test_idx, purge: bool, held_out=None) -> Fold:
    purged = 0
    if purge:
        train_idx, purged = _purge(df, train_idx, test_idx)
    classes = sorted(set(df["y"].iloc[test_idx].astype(int).tolist()))
    return Fold(name, np.sort(train_idx), np.sort(test_idx), classes, purged, held_out or {})


def capture_fold_assignment(captures: pd.DataFrame, n_splits: int, seed: int) -> Dict[str, int]:
    """Assign whole captures to folds, stratified by capture label. `captures` has capture_id, y."""
    per_class = captures.groupby("y")["capture_id"].nunique()
    k = int(min(n_splits, per_class.min()))
    if len(per_class) < 2 or k < 2:
        raise InfeasibleSplit(f"Need >=2 captures in each class for capture-grouped CV; have {per_class.to_dict()}")
    sgkf = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=seed)
    caps = captures.drop_duplicates("capture_id").reset_index(drop=True)
    assign: Dict[str, int] = {}
    for f, (_, te) in enumerate(sgkf.split(caps, caps["y"], groups=caps["capture_id"])):
        for cid in caps["capture_id"].iloc[te]:
            assign[cid] = f
    return assign


def make_folds(df: pd.DataFrame, protocol: str, seed: int = 42, n_splits: int = 5,
               capture_assignment: Optional[Dict[str, int]] = None, cutoff_year: Optional[int] = None) -> List[Fold]:
    """`df` must contain y, capture_id, behavioral_hash, dataset_id, family_group, collection_date."""
    if protocol not in PROTOCOLS:
        raise ValueError(f"Unknown protocol {protocol}")
    df = df.reset_index(drop=True)
    idx = np.arange(len(df))
    folds: List[Fold] = []

    if protocol == "BEHAVIORAL_HOLDOUT":
        gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
        tr, te = next(gss.split(df, df["y"], groups=df["behavioral_hash"]))
        folds.append(_make_fold(df, "holdout", tr, te, purge=False))

    elif protocol == "BEHAVIORAL_GROUP_KFOLD":
        sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
        for f, (tr, te) in enumerate(sgkf.split(df, df["y"], groups=df["behavioral_hash"])):
            folds.append(_make_fold(df, f"fold{f}", tr, te, purge=False))

    elif protocol == "CAPTURE_GROUP_KFOLD":
        assign = capture_assignment or capture_fold_assignment(df[["capture_id", "y"]].drop_duplicates(), n_splits, seed)
        fold_of = df["capture_id"].map(assign)
        if fold_of.isna().any():
            raise InfeasibleSplit("Some captures have no fold assignment")
        for f in sorted(fold_of.unique()):
            te = idx[fold_of.to_numpy() == f]
            tr = idx[fold_of.to_numpy() != f]
            folds.append(_make_fold(df, f"fold{int(f)}", tr, te, purge=True,
                                    held_out={"captures": sorted(df["capture_id"].iloc[te].unique().tolist())}))

    elif protocol == "LEAVE_ONE_SOURCE_OUT":
        for src in sorted(df["dataset_id"].unique()):
            te = idx[df["dataset_id"].to_numpy() == src]
            tr = idx[df["dataset_id"].to_numpy() != src]
            if df["y"].iloc[tr].nunique() < 2:
                folds.append(Fold(f"holdout_{src}", np.array([], dtype=int), te,
                                  sorted(set(df["y"].iloc[te].astype(int))), 0,
                                  {"source": src, "infeasible": "training side would contain a single class"}))
                continue
            folds.append(_make_fold(df, f"holdout_{src}", tr, te, purge=True, held_out={"source": src}))

    elif protocol == "LEAVE_ONE_FAMILY_OUT":
        mal = df[df["y"] == 1]
        families = sorted(mal["family_group"].unique())
        benign_caps = sorted(df.loc[df["y"] == 0, "capture_id"].unique())
        if not benign_caps:
            raise InfeasibleSplit("No benign captures")
        for i, fam in enumerate(families):
            bcap = benign_caps[i % len(benign_caps)]
            te_mask = ((df["y"] == 1) & (df["family_group"] == fam)) | (df["capture_id"] == bcap)
            te = idx[te_mask.to_numpy()]
            tr = idx[~te_mask.to_numpy()]
            folds.append(_make_fold(df, f"family_{fam}", tr, te, purge=True,
                                    held_out={"family_group": fam, "benign_capture": bcap}))

    elif protocol == "TEMPORAL_HOLDOUT":
        if cutoff_year is None:
            raise ValueError("TEMPORAL_HOLDOUT requires cutoff_year")
        years = pd.to_datetime(df["collection_date"], errors="coerce").dt.year
        te = idx[(years > cutoff_year).to_numpy()]
        tr = idx[(years <= cutoff_year).to_numpy()]
        if len(te) == 0 or df["y"].iloc[tr].nunique() < 2:
            raise InfeasibleSplit("Temporal holdout leaves an empty test set or a single-class training set")
        folds.append(_make_fold(df, f"after_{cutoff_year}", tr, te, purge=True, held_out={"cutoff_year": cutoff_year}))

    for f in folds:
        validate_fold(df, f)
    return folds


def validate_fold(df: pd.DataFrame, fold: Fold) -> None:
    if len(fold.train_idx) == 0:
        return
    if np.intersect1d(fold.train_idx, fold.test_idx).size:
        raise AssertionError(f"{fold.name}: rows appear in train and test")
    tr_groups = set(df["behavioral_hash"].iloc[fold.train_idx])
    te_groups = set(df["behavioral_hash"].iloc[fold.test_idx])
    shared = tr_groups & te_groups
    if shared:
        raise AssertionError(f"{fold.name}: {len(shared)} behavioral groups cross the train/test boundary")
