import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    precision_recall_curve, auc, precision_score,
    recall_score, f1_score, balanced_accuracy_score,
    confusion_matrix, roc_auc_score
)
from sklearn.model_selection import GroupShuffleSplit
import xgboost as xgb

def get_baseline_models():
    """
    Returns the baseline models for pilot evaluation.
    """
    return {
        "LogisticRegression": LogisticRegression(random_state=42, max_iter=1000, class_weight='balanced'),
        "RandomForest": RandomForestClassifier(random_state=42, class_weight='balanced'),
        "XGBoost": xgb.XGBClassifier(random_state=42, eval_metric='logloss') # XGBoost handles class weights during fit natively or via scale_pos_weight
    }

def evaluate_predictions(y_true, y_pred, y_prob=None):
    """
    Evaluates predictions rejecting raw accuracy in favor of PR-AUC, F1, etc.
    """
    results = {
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "balanced_accuracy": balanced_accuracy_score(y_true, y_pred)
    }

    if y_prob is not None:
        precision, recall, _ = precision_recall_curve(y_true, y_prob)
        results["pr_auc"] = auc(recall, precision)
        try:
            results["roc_auc"] = roc_auc_score(y_true, y_prob)
        except ValueError:
            results["roc_auc"] = None
    else:
        results["pr_auc"] = None
        results["roc_auc"] = None

    cm = confusion_matrix(y_true, y_pred)
    results["confusion_matrix"] = cm.tolist()

    return results

def group_aware_cross_validate(pipeline, X, y, groups, n_splits=5, random_state=42):
    """
    Performs group-aware cross-validation ensuring duplicate behaviors
    don't cross train/test boundaries.
    """
    gss = GroupShuffleSplit(n_splits=n_splits, test_size=0.2, random_state=random_state)

    fold_results = []

    for fold, (train_idx, test_idx) in enumerate(gss.split(X, y, groups)):
        X_train, y_train = X.iloc[train_idx], y.iloc[train_idx]
        X_test, y_test = X.iloc[test_idx], y.iloc[test_idx]

        # Fit strictly on train split
        pipeline.fit(X_train, y_train)

        # Predict on test split
        y_pred = pipeline.predict(X_test)
        if hasattr(pipeline, "predict_proba"):
            y_prob = pipeline.predict_proba(X_test)[:, 1]
        else:
            y_prob = None

        metrics = evaluate_predictions(y_test, y_pred, y_prob)
        metrics['fold'] = fold + 1
        metrics['train_samples'] = len(train_idx)
        metrics['test_samples'] = len(test_idx)

        fold_results.append(metrics)

    return fold_results
