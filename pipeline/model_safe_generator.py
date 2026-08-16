"""
Phase 6 Step 7: Leakage-Controlled Model-Safe Dataset Generator
"""
import pandas as pd
from typing import Tuple, List, Dict
import hashlib
import time

PROVENANCE_COLUMNS = [
    "flow_id",
    "dataset_id",
    "source_file"
]

TARGET_COLUMN = "label"

FORBIDDEN_KEYWORDS = [
    "ip", "port", "mac", "timestamp", "time", "date", "year", "month", "domain"
]

def generate_model_safe_split(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, Dict]:
    """
    Splits the processed features dataframe into:
    1. A strictly model-safe feature dataframe
    2. A provenance/audit dataframe

    Returns (model_safe_df, provenance_df, manifest_dict)
    """
    original_columns = set(df.columns)

    # Identify provenance columns
    prov_cols = [c for c in PROVENANCE_COLUMNS if c in original_columns]

    # We must construct a safe ID to link provenance without exposing original flow_id.
    # The original flow_id is a hash, but just to be completely disjoint, we use an integer index.

    # Create the provenance table
    provenance_df = df[prov_cols + ([TARGET_COLUMN] if TARGET_COLUMN in df.columns else [])].copy()
    provenance_df.insert(0, "model_safe_index", range(len(provenance_df)))

    # Create model safe table
    # Base it on all columns minus provenance
    model_safe_cols = [c for c in original_columns if c not in prov_cols]

    # Explicitly enforce FORBIDDEN features
    # Note: 'relative_times' has 'time' but is safe relative timing, 'sni_present' has no forbidden keyword.
    # But wait, relative_times is a sequence. It's allowed if downstream uses it.
    # Let's rigorously filter forbidden keywords but whitelist known safe ones.
    SAFE_WHITELIST = [
        "packet_count_asymmetry", "byte_count_asymmetry",
        "sequence_relative_times", "relative_times",
        "packets_per_second", "bytes_per_second" # 'second' isn't in keywords but just in case
    ]

    final_safe_cols = []
    excluded_cols = prov_cols.copy()

    for c in model_safe_cols:
        if c == TARGET_COLUMN:
            final_safe_cols.append(c)
            continue

        is_safe = True

        # Check raw SNI or dataset names explicitly
        if c in ["sni", "sni_domain", "dataset_name", "capture_source"]:
            is_safe = False

        # Check forbidden keywords
        if is_safe and c not in SAFE_WHITELIST:
            c_lower = c.lower()
            for kw in FORBIDDEN_KEYWORDS:
                if kw in c_lower:
                    is_safe = False
                    break

        if is_safe:
            final_safe_cols.append(c)
        else:
            excluded_cols.append(c)

    # Assemble model safe dataframe
    model_safe_df = df[final_safe_cols].copy()
    model_safe_df.insert(0, "model_safe_index", range(len(model_safe_df)))

    # Duplicate checking
    # Exclude index and label for duplicate feature check
    feature_cols = [c for c in model_safe_df.columns if c not in ["model_safe_index", TARGET_COLUMN]]
    # Sequences cannot be hashed easily by drop_duplicates, so drop sequence cols for dupe check
    flat_feature_cols = [c for c in feature_cols if not c.startswith("sequence_")]

    duplicates_mask = model_safe_df.duplicated(subset=flat_feature_cols, keep=False)
    duplicate_count = duplicates_mask.sum()

    # Manifest creation
    manifest = {
        "schema_version": "1.0",
        "pipeline_version": "Phase6_Step7",
        "generation_timestamp": time.time(),
        "input_rows": len(df),
        "output_rows": len(model_safe_df),
        "total_columns": len(original_columns),
        "model_safe_columns": len(model_safe_df.columns),
        "excluded_columns": excluded_cols,
        "duplicate_count": int(duplicate_count),
        "missing_value_policy": "Semantic missingness preserved natively as null/NaN. No imputation performed.",
        "leakage_check": "Provenance and known forbidden string subsets (ip, port, mac, timestamp, absolute time, raw domains) actively stripped."
    }

    return model_safe_df, provenance_df, manifest
