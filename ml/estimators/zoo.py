"""
Baseline model zoo with small, pre-declared hyper-parameter grids.

Grids are deliberately small: model selection happens inside the training fold (nested
capture-grouped CV), and compute must stay affordable on a CPU-only workstation.
Class imbalance is handled by class weighting inside the estimator; no resampling is used
in the headline benchmark (resampling, if ever enabled, would run inside the training fold).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List

from sklearn.dummy import DummyClassifier
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression


@dataclass
class ModelSpec:
    name: str
    factory: Callable[..., Any]
    grid: List[Dict[str, Any]]
    scale: bool
    exportable: bool
    description: str
    defaults: Dict[str, Any] = field(default_factory=dict)

    def build(self, seed: int, **params):
        merged = {**self.defaults, **params}
        return self.factory(seed=seed, **merged)


def _dummy(seed, **p):
    return DummyClassifier(strategy="prior")


def _logreg(seed, C=1.0):
    return LogisticRegression(C=C, class_weight="balanced", max_iter=4000, random_state=seed)


def _rf(seed, min_samples_leaf=1, max_features="sqrt", n_estimators=150):
    return RandomForestClassifier(n_estimators=n_estimators, min_samples_leaf=min_samples_leaf, max_features=max_features,
                                  class_weight="balanced_subsample", n_jobs=-1, random_state=seed)


def _et(seed, min_samples_leaf=1, n_estimators=150):
    return ExtraTreesClassifier(n_estimators=n_estimators, min_samples_leaf=min_samples_leaf, class_weight="balanced",
                                n_jobs=-1, random_state=seed)


def _hgb(seed, learning_rate=0.1, max_leaf_nodes=31):
    return HistGradientBoostingClassifier(learning_rate=learning_rate, max_leaf_nodes=max_leaf_nodes, max_iter=100,
                                          class_weight="balanced", early_stopping=False, random_state=seed)


MODEL_SPECS: Dict[str, ModelSpec] = {
    "dummy_prior": ModelSpec("dummy_prior", _dummy, [{}], False, False,
                             "Predicts the training prevalence; the floor every model must beat."),
    "logreg": ModelSpec("logreg", _logreg, [{"C": 0.1}, {"C": 1.0}, {"C": 10.0}], True, True,
                        "L2 logistic regression, balanced class weights, standardised inputs."),
    "random_forest": ModelSpec("random_forest", _rf, [{"min_samples_leaf": 1}, {"min_samples_leaf": 5}], False, True,
                               "Random forest (150 trees), balanced-subsample weights."),
    "extra_trees": ModelSpec("extra_trees", _et, [{"min_samples_leaf": 1}, {"min_samples_leaf": 5}], False, True,
                             "Extremely randomised trees (150 trees), balanced weights."),
    "hist_gb": ModelSpec("hist_gb", _hgb, [{"learning_rate": 0.05, "max_leaf_nodes": 15}, {"learning_rate": 0.1, "max_leaf_nodes": 31}],
                         False, False, "Histogram gradient boosting (100 iterations), balanced weights. Benchmark only (not exportable)."),
}
