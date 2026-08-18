import pytest
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from pipeline.modeling import group_aware_cross_validate, evaluate_predictions

@pytest.fixture
def dummy_data():
    X = pd.DataFrame({
        'feat1': np.random.randn(20),
        'feat2': np.random.randn(20)
    })
    y = pd.Series(np.random.randint(0, 2, 20))
    groups = pd.Series([
        'g1', 'g1', 'g2', 'g2', 'g3', 'g4', 'g5', 'g6', 'g7', 'g8',
        'g9', 'g9', 'g10', 'g11', 'g12', 'g13', 'g14', 'g15', 'g16', 'g17'
    ])
    return X, y, groups

def test_evaluate_predictions():
    y_true = np.array([0, 1, 1, 0, 1])
    y_pred = np.array([0, 1, 0, 0, 1])
    y_prob = np.array([0.1, 0.9, 0.4, 0.2, 0.8])

    results = evaluate_predictions(y_true, y_pred, y_prob)

    assert "precision" in results
    assert "recall" in results
    assert "f1" in results
    assert "pr_auc" in results
    assert "confusion_matrix" in results
    assert "balanced_accuracy" in results

def test_group_aware_cv(dummy_data):
    X, y, groups = dummy_data

    pipeline = Pipeline([
        ('clf', LogisticRegression(random_state=42))
    ])

    # 2 splits to be fast
    results = group_aware_cross_validate(pipeline, X, y, groups, n_splits=2)

    assert len(results) == 2
    for r in results:
        assert r['test_samples'] > 0
        assert r['train_samples'] > 0
        # The total samples may not exactly equal 20 since GroupShuffleSplit splits by group,
        # but train + test should be 20.
        assert r['train_samples'] + r['test_samples'] == 20
