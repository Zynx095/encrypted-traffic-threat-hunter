"""
Adapter for DS-004 (CipherSpectrum).
"""
from pathlib import Path
from typing import List, Dict, Any

from .base import DatasetAdapter
from pipeline import config

class DS004Adapter(DatasetAdapter):
    dataset_id = "DS-004"
    dataset_name = "CipherSpectrum"
    research_role = "BENIGN_VALIDATION"

    def discover(self) -> List[Path]:
        pcaps = []
        ds004_raw = config.RAW_DATA_DIR / "ds004"
        if ds004_raw.exists():
            pcaps.extend(ds004_raw.rglob("*.pcap"))
        if config.SAMPLES_DS004_DIR.exists():
            pcaps.extend(config.SAMPLES_DS004_DIR.rglob("*.pcap"))
        return pcaps

    def extract_metadata(self, filepath: Path) -> Dict[str, Any]:
        return {
            "source_filename": filepath.name,
            "environment": "ENTERPRISE_NETWORK",
            "application_label": "UNKNOWN"
        }

    def normalize_metadata(self, raw_metadata: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "label_original": raw_metadata["application_label"],
            "label_normalized": "BENIGN_VALIDATION",
            "label_source": "cipherspectrum_metadata",
            "label_confidence": "HIGH",
            "malware_family": "UNKNOWN",
            "capture_environment": raw_metadata["environment"]
        }
