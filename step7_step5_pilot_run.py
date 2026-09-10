import os
import json
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from pipeline.preprocessing import get_full_pipeline
from pipeline.modeling import get_baseline_models, group_aware_cross_validate
from pipeline.experimental_dataset_constructor import ExperimentConstructor
from sklearn.model_selection import GroupShuffleSplit
import traceback

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
RANDOM_STATE = 42
OUTPUT_DIR = Path('data/experiments/phase7_step5_pilot')
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

LEAKAGE_COLUMNS = [
    'behavioral_hash', 'flow_id', 'source_ip', 'destination_ip', 
    'source_port', 'destination_port', 'timestamp', 'dataset_id',
    'pcap_filename', 'mac_address', 'model_safe_index', 'corpus_sample_id'
]

def leakage_audit(df):
    for col in LEAKAGE_COLUMNS:
        if col in df.columns:
            logger.error(f"LEAKAGE DETECTED: Column '{col}' found in model input matrix.")
            raise ValueError(f"Leakage check failed. Column {col} must not be in model features.")
    
    if 'label' in df.columns:
        raise ValueError("Label column found in model input matrix.")

def map_labels(y_series):
    return y_series.apply(lambda x: 1 if 'MALICIOUS' in str(x) else 0)

def main():
    all_fold_results = []
    pilot_summary = {}

    models = get_baseline_models()
    
    ms_df = pd.read_parquet('data/processed/v2/model_safe/model_safe_dataset.parquet')
    prov_df = pd.read_parquet('data/processed/v2/model_safe/provenance_metadata.parquet')
    
    constructor = ExperimentConstructor(ms_df, prov_df)
    full_df = constructor.full_df # This contains 'behavioral_hash' and all features!
    
    experiments = {
        'A_flow': constructor.flow_stat_cols + constructor.tls_structural_cols,
        'B_ja3': ['ja3_hash'],
        'C_ja4': ['ja4'],
        'D_ja3_flow': ['ja3_hash'] + constructor.flow_stat_cols + constructor.tls_structural_cols,
        'E_ja4_flow': ['ja4'] + constructor.flow_stat_cols + constructor.tls_structural_cols
    }
    
    for exp_name, feature_cols in experiments.items():
        logger.info(f"Running Experiment: {exp_name}")
        
        cols = ['label', 'behavioral_hash'] + feature_cols
        
        # Filter full_df for non-null fingerprint requirements
        df_exp = full_df[cols].copy()
        if 'ja3_hash' in feature_cols:
            df_exp = df_exp[df_exp['ja3_hash'].notnull()]
        if 'ja4' in feature_cols:
            df_exp = df_exp[df_exp['ja4'].notnull()]
            
        groups = df_exp['behavioral_hash']
        y = map_labels(df_exp['label'])
        X = df_exp.drop(columns=['label', 'behavioral_hash'])
        X = X.drop(columns=[c for c in LEAKAGE_COLUMNS if c in X.columns], errors='ignore')
        
        # Leakage Audit
        leakage_audit(X)
        
        numeric_features = X.select_dtypes(include=[np.number]).columns.tolist()
        categorical_features = X.select_dtypes(exclude=[np.number]).columns.tolist()
        
        total_samples = len(X)
        malicious_count = sum(y == 1)
        benign_count = sum(y == 0)
        missing_counts = X.isnull().sum().sum()
        
        exp_summary = {
            "sample_count": total_samples,
            "feature_count": X.shape[1],
            "malicious_count": malicious_count,
            "benign_count": benign_count,
            "class_ratio": f"{malicious_count}:{benign_count}",
            "missing_values": int(missing_counts),
            "groups_count": groups.nunique(),
            "models": {}
        }
        
        gss = GroupShuffleSplit(n_splits=5, test_size=0.2, random_state=RANDOM_STATE)
        
        for model_name, model in models.items():
            logger.info(f"  Evaluating Model: {model_name}")
            
            pipeline = get_full_pipeline(
                numeric_features=numeric_features,
                categorical_features=categorical_features,
                model=model,
                resampler=None,
                scale_numeric=True
            )
            
            fold_metrics = []
            
            try:
                for fold, (train_idx, test_idx) in enumerate(gss.split(X, y, groups)):
                    train_groups = set(groups.iloc[train_idx])
                    test_groups = set(groups.iloc[test_idx])
                    
                    if not train_groups.isdisjoint(test_groups):
                        raise RuntimeError("intersection(train_groups, test_groups) != empty")
                    
                    X_train, y_train = X.iloc[train_idx], y.iloc[train_idx]
                    X_test, y_test = X.iloc[test_idx], y.iloc[test_idx]
                    
                    # We might have 0 benign samples in testing because of the extreme imbalance + GroupShuffleSplit
                    if sum(y_test == 0) == 0:
                        logger.warning(f"Fold {fold+1}: 0 benign samples in test set.")
                        
                    pipeline.fit(X_train, y_train)
                    y_pred = pipeline.predict(X_test)
                    
                    if hasattr(pipeline, "predict_proba"):
                        try:
                            y_prob = pipeline.predict_proba(X_test)[:, 1]
                        except:
                            y_prob = None
                    else:
                        y_prob = None
                        
                    from pipeline.modeling import evaluate_predictions
                    metrics = evaluate_predictions(y_test, y_pred, y_prob)
                    
                    metrics['experiment'] = exp_name
                    metrics['model'] = model_name
                    metrics['fold'] = fold + 1
                    metrics['train_samples'] = len(train_idx)
                    metrics['test_samples'] = len(test_idx)
                    
                    fold_metrics.append(metrics)
                    all_fold_results.append(metrics)
                    
                exp_summary["models"][model_name] = {
                    "cv_status": "COMPLETED",
                    "avg_pr_auc": np.nanmean([m['pr_auc'] for m in fold_metrics if m['pr_auc'] is not None]),
                    "avg_f1": np.nanmean([m['f1'] for m in fold_metrics])
                }
                
            except Exception as e:
                logger.error(f"CV INFEASIBLE for {exp_name} - {model_name}: {e}")
                traceback.print_exc()
                exp_summary["models"][model_name] = {
                    "cv_status": "INFEASIBLE",
                    "reason": str(e)
                }

        pilot_summary[exp_name] = exp_summary

    pd.DataFrame(all_fold_results).to_csv(OUTPUT_DIR / 'pilot_fold_results.csv', index=False)
    with open(OUTPUT_DIR / 'pilot_summary.json', 'w') as f:
        json.dump(pilot_summary, f, indent=4)
        
    logger.info("Pilot evaluation completed successfully.")

if __name__ == '__main__':
    main()
