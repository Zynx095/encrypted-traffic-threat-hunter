import os
import pandas as pd
import numpy as np
from pipeline.feature_extraction import build_feature_record
import logging

logging.basicConfig(level=logging.INFO)

def run_validation():
    features_path = "E:/UserBenchmark/encrypted-traffic-threat-hunter/data/processed/features/flows_behavioral_features.parquet"
    if not os.path.exists(features_path):
        logging.error("Features file not found.")
        return
        
    df = pd.read_parquet(features_path)
    
    # 1. Basic Counts
    num_flows = len(df)
    feature_cols = [c for c in df.columns if not c.startswith("sequence_") and c not in ["flow_id", "dataset_id", "source_file"]]
    num_features = len(feature_cols)
    
    print("=== Phase 6 Step 6 Validation Report ===")
    print(f"Flows processed/generated: {num_flows}")
    print(f"Total columns: {len(df.columns)}")
    print(f"Feature count (excluding seq/meta): {num_features}")
    
    # 2. Distributions
    print("\nLabel Distribution:")
    print(df['label'].value_counts().to_string())
    
    print("\nTLS Version Distribution:")
    print(df['tls_version'].value_counts(dropna=False).to_string())
    
    # 3. Availabilities
    seq_avail = df['sequence_packet_lengths'].notnull().sum()
    print(f"\nSequence Availability: {seq_avail} / {num_flows}")
    
    ja3_avail = df['ja3_hash'].notnull().sum()
    ja3s_avail = df['ja3s_hash'].notnull().sum()
    ja4_avail = df['ja4'].notnull().sum()
    
    print(f"JA3 Availability: {ja3_avail} / {num_flows}")
    print(f"JA3S Availability: {ja3s_avail} / {num_flows}")
    print(f"JA4 Availability: {ja4_avail} / {num_flows}")
    
    # 4. Missing Values
    missing = df[feature_cols].isnull().sum()
    print("\nMissing-value counts (top 10):")
    print(missing.sort_values(ascending=False).head(10).to_string())
    
    # 5. Constraints Check
    violations = 0
    
    # Negative checks
    if (df['flow_duration'] < 0).any():
        print("VIOLATION: Negative duration found.")
        violations += 1
    if (df['total_packets'] < 0).any():
        print("VIOLATION: Negative packet count found.")
        violations += 1
    if (df['total_bytes'] < 0).any():
        print("VIOLATION: Negative byte count found.")
        violations += 1
        
    # Additive checks
    if not (df['forward_packets'] + df['reverse_packets'] == df['total_packets']).all():
        print("VIOLATION: fwd + rev packets != total packets")
        violations += 1
    if not (df['forward_bytes'] + df['reverse_bytes'] == df['total_bytes']).all():
        print("VIOLATION: fwd + rev bytes != total bytes")
        violations += 1
        
    # Infinite checks
    numeric_df = df.select_dtypes(include=[np.number])
    if np.isinf(numeric_df).any().any():
        print("VIOLATION: Infinite values found.")
        violations += 1
        
    # Sequence length match
    # Since parquet stores sequence as arrays, check lengths
    lengths = df['sequence_packet_lengths'].apply(len)
    if not (lengths == df['total_packets']).all():
        print("VIOLATION: sequence_packet_lengths len != total_packets")
        violations += 1
        
    # Leakage checks
    cols = df.columns.str.lower()
    for kw in ["ip", "port", "timestamp"]:
        if any(kw in c for c in cols):
            if not all(c in ["forward_packet_ratio", "reverse_packet_ratio", "packets_per_second"] for c in cols if kw in c): # Handle false positive 'ip' in 'ratio'/'cip' etc if any, but wait, 'ip' is in 'description'. Wait, 'ip' is in 'sni_present'? No. 'ip' is in 'multiple'. 'ip' is NOT in 'ratio'. 'ratio' has no 'ip'.
                # Actually, check exact matches or obvious leakage
                suspects = [c for c in cols if kw in c]
                if suspects:
                    print(f"VIOLATION: Potential leakage column found: {suspects}")
                    violations += 1
                    
    # Exact SNI
    if 'sni' in df.columns or 'sni_string' in df.columns or 'sni_domain' in df.columns:
        print("VIOLATION: Raw SNI column found.")
        violations += 1

    print(f"\nTotal Constraint Violations: {violations}")
    
    # 6. Deterministic Check
    # Grab the first raw interim row and build feature record twice
    interim_path = "E:/UserBenchmark/encrypted-traffic-threat-hunter/data/interim/flows/sample1_flows.parquet"
    if os.path.exists(interim_path):
        raw_df = pd.read_parquet(interim_path)
        row_dict = raw_df.iloc[0].to_dict()
        rec1 = build_feature_record(row_dict)
        rec2 = build_feature_record(row_dict)
        if rec1 == rec2:
            print("\nDeterministic reproducibility check: PASSED")
        else:
            print("\nDeterministic reproducibility check: FAILED")
            
if __name__ == '__main__':
    run_validation()
