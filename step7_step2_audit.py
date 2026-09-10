import os
import json
import pandas as pd
import numpy as np
from pathlib import Path

def audit():
    v2_exp = Path("data/processed/v2/experiments")
    datasets = {
        "A": v2_exp / "A_flow_only.parquet",
        "B": v2_exp / "B_ja3_only.parquet",
        "C": v2_exp / "C_ja4_only.parquet",
        "D": v2_exp / "D_ja3_flow.parquet",
        "E": v2_exp / "E_ja4_flow.parquet"
    }

    audit_res = {}
    feature_summaries = []

    for name, path in datasets.items():
        if not path.exists():
            continue
            
        df = pd.read_parquet(path)
        
        malicious = int((df["label"] == "MALICIOUS").sum()) if "label" in df.columns else 0
        benign = int((df["label"] == "BENIGN_VALIDATION").sum()) if "label" in df.columns else 0
        
        audit_res[name] = {
            "rows": len(df),
            "cols": len(df.columns),
            "malicious": malicious,
            "benign_validation": benign,
            "missing_label": int(df["label"].isnull().sum()) if "label" in df.columns else 0
        }
        
        # Missingness & Cardinality
        for col in df.columns:
            missing = int(df[col].isnull().sum())
            non_missing = len(df) - missing
            missing_pct = missing / len(df) if len(df) > 0 else 0.0
            
            # Handle unhashable types like ndarray
            try:
                unique_count = int(df[col].nunique(dropna=True))
            except TypeError:
                unique_count = -1
            
            summary = {
                "dataset": name,
                "feature": col,
                "type": str(df[col].dtype),
                "missing_count": missing,
                "missing_pct": round(missing_pct, 4),
                "unique_count": unique_count
            }
            
            if pd.api.types.is_numeric_dtype(df[col]):
                summary["min"] = float(df[col].min()) if non_missing > 0 else None
                summary["max"] = float(df[col].max()) if non_missing > 0 else None
                summary["mean"] = float(df[col].mean()) if non_missing > 0 else None
            
            if df[col].dtype == object or df[col].dtype.name == "category" or df[col].dtype == bool:
                if non_missing > 0 and unique_count > -1:
                    try:
                        top_val = df[col].value_counts().index[0]
                        top_freq = int(df[col].value_counts().iloc[0])
                        summary["top_value"] = str(top_val)
                        summary["top_value_freq"] = top_freq
                    except TypeError:
                        pass
                    
            feature_summaries.append(summary)

    # Output JSON and CSV
    out_dir = Path("data/manifests")
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "phase7_step2_statistical_audit.json", "w") as f:
        json.dump(audit_res, f, indent=2)
        
    df_feat = pd.DataFrame(feature_summaries)
    df_feat.to_csv("data/verification/results/phase7_step2_feature_summary.csv", index=False)
    print("Audit generated.")

if __name__ == "__main__":
    audit()
