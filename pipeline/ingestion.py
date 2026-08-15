"""
Core ingestion orchestrator for Phase 6 Step 2.
"""
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

from pipeline import config
from pipeline.hashing import compute_sha256
from pipeline.pcap_validator import validate_pcap
from pipeline.adapters.base import DatasetAdapter
from pipeline.manifest import write_manifest_csv, write_manifest_json

logger = logging.getLogger(__name__)

def ingest_dataset(adapter: DatasetAdapter) -> List[Dict[str, Any]]:
    records = []
    pcaps = adapter.discover()
    logger.info(f"Discovered {len(pcaps)} files for {adapter.dataset_id}")
    for pcap in pcaps:
        record = {
            "dataset_id": adapter.dataset_id,
            "dataset_name": adapter.dataset_name,
            "source_file": pcap.name,
            "relative_path": str(pcap.relative_to(config.PROJECT_ROOT)) if pcap.is_relative_to(config.PROJECT_ROOT) else str(pcap),
            "file_size_bytes": "UNKNOWN",
            "sha256": "UNKNOWN",
            "format": "UNKNOWN",
            "packet_count": "UNKNOWN",
            "validation_status": "UNKNOWN",
            "validation_reason": "UNKNOWN",
            "malware_family": "UNKNOWN",
            "original_label": "UNKNOWN",
            "research_role": adapter.research_role,
            "ingestion_status": "PENDING",
            "pipeline_version": config.PIPELINE_VERSION,
            "ingestion_timestamp": datetime.utcnow().isoformat() + "Z"
        }
        try:
            record["file_size_bytes"] = pcap.stat().st_size
            record["sha256"] = compute_sha256(pcap)
            val_result = validate_pcap(pcap)
            record["validation_status"] = val_result.status
            record["validation_reason"] = val_result.reason
            record["format"] = val_result.format
            if val_result.packet_count is not None:
                record["packet_count"] = val_result.packet_count
            raw_meta = adapter.extract_metadata(pcap)
            norm_meta = adapter.normalize_metadata(raw_meta)
            record["original_label"] = norm_meta.get("label_original", "UNKNOWN")
            record["malware_family"] = norm_meta.get("malware_family", "UNKNOWN")
            record["ingestion_status"] = "SUCCESS" if val_result.status == "VALID" else "SKIPPED"
        except Exception as e:
            logger.error(f"Error ingesting {pcap}: {e}")
            record["ingestion_status"] = "ERROR"
            record["validation_reason"] = str(e)
        records.append(record)
    return records

def run_ingestion(adapters: List[DatasetAdapter]) -> List[Dict[str, Any]]:
    all_records = []
    for adapter in adapters:
        records = ingest_dataset(adapter)
        all_records.extend(records)
    config.MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    csv_path = config.MANIFEST_DIR / f"dataset_manifest_{timestamp}.csv"
    json_path = config.MANIFEST_DIR / f"dataset_manifest_{timestamp}.json"
    write_manifest_csv(all_records, csv_path)
    write_manifest_json(all_records, json_path)
    logger.info(f"Ingestion complete. Manifest written to {csv_path}")
    return all_records

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    from pipeline.adapters.ds004 import DS004Adapter
    from pipeline.adapters.ds008 import DS008Adapter
    from pipeline.adapters.ds006 import DS006Adapter
    from pipeline.adapters.ds007 import DS007Adapter
    
    adapters = [DS008Adapter(), DS004Adapter(), DS006Adapter(), DS007Adapter()]
    run_ingestion(adapters)
