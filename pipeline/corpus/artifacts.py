"""
Per-artifact provenance manifest.

Each entry traces one file to its dataset, capture, checksum, acquisition reference,
processing step and verification outcome. Tiers: RAW (original capture bytes),
INTERIM (reconstructed flows), PROCESSED (feature tables). Raw files are never rewritten;
a changed checksum for an existing artifact id is recorded as a verification failure,
never silently replaced.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline.corpus import paths

TIERS = ("RAW", "INTERIM", "PROCESSED")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


class ArtifactManifest:
    def __init__(self, path: Path = paths.ARTIFACT_MANIFEST_PATH):
        self.path = Path(path)
        self.entries: Dict[str, Dict[str, Any]] = {}
        if self.path.exists():
            for e in json.loads(self.path.read_text(encoding="utf-8")).get("artifacts", []):
                self.entries[e["artifact_id"]] = e

    def record(self, artifact_id: str, *, tier: str, dataset_id: str, path: str, sha256: Optional[str],
               size_bytes: Optional[int], capture_id: Optional[str] = None, source_url: Optional[str] = None,
               acquisition: Optional[Dict[str, Any]] = None, derived_from: Optional[List[str]] = None,
               processing: Optional[Dict[str, Any]] = None, label: Optional[Dict[str, Any]] = None,
               verification: Optional[Dict[str, Any]] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if tier not in TIERS:
            raise ValueError(f"Unknown tier {tier}")
        previous = self.entries.get(artifact_id)
        entry = {
            "artifact_id": artifact_id,
            "tier": tier,
            "dataset_id": dataset_id,
            "capture_id": capture_id,
            "path": path,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "source_url": source_url,
            "acquisition": acquisition or {},
            "derived_from": derived_from or [],
            "processing": processing or {},
            "label": label or {},
            "verification": verification or {},
            "metadata": metadata or {},
            "recorded_at": _now(),
        }
        if previous and tier == "RAW" and previous.get("sha256") and sha256 and previous["sha256"] != sha256:
            entry["verification"] = dict(entry["verification"])
            entry["verification"]["status"] = "FAILED"
            entry["verification"].setdefault("checks", []).append({
                "check": "raw_checksum_stable",
                "passed": False,
                "detail": f"Previously recorded sha256 {previous['sha256']} differs from {sha256}.",
            })
        self.entries[artifact_id] = entry
        return entry

    def by_tier(self, tier: str) -> List[Dict[str, Any]]:
        return [e for e in self.entries.values() if e["tier"] == tier]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema_version": "1.0", "generated_at": _now(),
                   "artifacts": [self.entries[k] for k in sorted(self.entries)]}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)
