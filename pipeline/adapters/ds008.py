"""
Adapter for DS-008 (Malware-Traffic-Analysis.net).
"""
import re
from pathlib import Path
from typing import List, Dict, Any

from .base import DatasetAdapter
from pipeline import config

class DS008Adapter(DatasetAdapter):
    dataset_id = "DS-008"
    dataset_name = "Malware-Traffic-Analysis.net"
    research_role = "PRIMARY_MODERN_TLS_MALWARE"

    def discover(self) -> List[Path]:
        pcaps = []
        ds008_raw = config.RAW_DATA_DIR / "ds008"
        if ds008_raw.exists():
            pcaps.extend(ds008_raw.rglob("*.pcap"))
            pcaps.extend(ds008_raw.rglob("*.pcapng"))
        if config.VERIFICATION_PCAPS_DIR.exists():
            for p in config.VERIFICATION_PCAPS_DIR.glob("*.pcap"):
                if re.match(r'^\d{4}-\d{2}-\d{2}', p.name):
                    pcaps.append(p)
        return pcaps

    def extract_metadata(self, filepath: Path) -> Dict[str, Any]:
        filename = filepath.name
        metadata = {
            "source_filename": filename,
            "capture_date": "UNKNOWN",
            "family": "UNKNOWN",
            "environment": "SANDBOX"
        }
        match = re.match(r'^(\d{4}-\d{2}-\d{2})-(.*?)-infection-traffic', filename)
        if match:
            metadata["capture_date"] = match.group(1)
            metadata["family"] = match.group(2)
        return metadata

    def normalize_metadata(self, raw_metadata: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "label_original": raw_metadata["family"],
            "label_normalized": "MALICIOUS",
            "label_source": "mta_filename_convention",
            "label_confidence": "HIGH",
            "malware_family": raw_metadata["family"],
            "capture_environment": raw_metadata["environment"],
            "capture_date": raw_metadata["capture_date"]
        }
