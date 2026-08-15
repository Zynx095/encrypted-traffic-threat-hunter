import os
import pandas as pd
import glob
import json

def validate_extraction():
    data_dir = "E:/UserBenchmark/encrypted-traffic-threat-hunter/data/interim/flows"
    parquet_files = glob.glob(os.path.join(data_dir, "*.parquet"))
    
    validation_results = []
    
    ds004_success = 0
    ds008_success = 0
    ds004_total = 0
    ds008_total = 0
    
    for p_file in parquet_files:
        df = pd.read_parquet(p_file)
        # Filter flows that have TLS candidate
        tls_flows = df[df['clienthello_present'] == True]
        
        for _, row in tls_flows.iterrows():
            ds_id = row['dataset_id']
            src_file = row['source_file']
            
            if ds_id == 'DS-004':
                ds004_total += 1
                if pd.notnull(row['ja4']): ds004_success += 1
            if ds_id == 'DS-008':
                ds008_total += 1
                if pd.notnull(row['ja4']): ds008_success += 1
                
            res = {
                "dataset_id": ds_id,
                "source_file": src_file,
                "flow_id": row['flow_id'],
                "tls_version": row['tls_version'],
                "clienthello_present": row['clienthello_present'],
                "serverhello_present": row['serverhello_present'],
                "ja3_available": pd.notnull(row['ja3_hash']),
                "ja3s_available": pd.notnull(row['ja3s_hash']),
                "ja4_available": pd.notnull(row['ja4']),
                "extraction_status": "SUCCESS" if pd.notnull(row['ja4']) else "FAILED"
            }
            validation_results.append(res)
            
    val_df = pd.DataFrame(validation_results)
    out_csv = "E:/UserBenchmark/encrypted-traffic-threat-hunter/data/verification/results/phase6_step5_validation.csv"
    val_df.to_csv(out_csv, index=False)
    
    print(f"Validation Table written to {out_csv}")
    print(f"Total TLS Flows Evaluated: {len(val_df)}")
    print(f"DS-004 JA4 Success Rate: {ds004_success} / {ds004_total}")
    print(f"DS-008 JA4 Success Rate: {ds008_success} / {ds008_total}")
    
    # Let's read old DS-004 verification results to cross-check
    old_ds004 = "E:/UserBenchmark/encrypted-traffic-threat-hunter/data/verification/output/ds004_verification_results.json"
    if os.path.exists(old_ds004):
        with open(old_ds004, 'r') as f:
            old_res = json.load(f)
            print("\nCross-checking with previous DS-004 verification:")
            for r in old_res:
                f_name = r['file']
                old_success = r['ja4_success']
                # Check new
                new_success = val_df[(val_df['source_file'] == f_name) & (val_df['ja4_available'] == True)].shape[0]
                status = "MATCH" if old_success == new_success else f"MISMATCH ({old_success} vs {new_success})"
                print(f"  {f_name}: {status}")

if __name__ == "__main__":
    validate_extraction()
