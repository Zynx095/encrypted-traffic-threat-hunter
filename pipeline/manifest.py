"""
Manifest generation for Phase 6 pipeline.
"""
import csv
import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from pipeline import config

def write_manifest_csv(records: List[Dict[str, Any]], filepath: Path):
    if not records:
        return
    filepath.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "dataset_id", "dataset_name", "source_file", "relative_path",
        "file_size_bytes", "sha256", "format", "packet_count",
        "validation_status", "validation_reason", "malware_family",
        "original_label", "research_role", "ingestion_status",
        "pipeline_version", "ingestion_timestamp"
    ]
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for row in records:
            writer.writerow(row)

def write_manifest_json(records: List[Dict[str, Any]], filepath: Path):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump({
            "pipeline_version": config.PIPELINE_VERSION,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "records": records
        }, f, indent=2)
