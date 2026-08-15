import os
import glob
import pandas as pd
import logging
from pipeline.feature_extraction import build_feature_record

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_step6():
    input_dir = "E:/UserBenchmark/encrypted-traffic-threat-hunter/data/interim/flows"
    output_dir = "E:/UserBenchmark/encrypted-traffic-threat-hunter/data/processed/features"
    os.makedirs(output_dir, exist_ok=True)
    
    parquet_files = glob.glob(os.path.join(input_dir, "*.parquet"))
    
    all_feature_records = []
    
    for p_file in parquet_files:
        logger.info(f"Extracting features from {os.path.basename(p_file)}...")
        df = pd.read_parquet(p_file)
        
        for _, row in df.iterrows():
            record = build_feature_record(row.to_dict())
            all_feature_records.append(record)
            
    if not all_feature_records:
        logger.warning("No flows found.")
        return
        
    out_df = pd.DataFrame(all_feature_records)
    out_path = os.path.join(output_dir, "flows_behavioral_features.parquet")
    out_df.to_parquet(out_path, index=False)
    
    logger.info(f"Wrote {len(out_df)} feature records to {out_path}")

if __name__ == '__main__':
    run_step6()
