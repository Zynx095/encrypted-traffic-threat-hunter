"""
Dataset acquisition registry with evidence-backed lifecycle transitions.

Unknown facts are stored as the literal string "UNKNOWN" and are never inferred.
A state change is only accepted if it is a legal transition AND its guard conditions are
satisfied by recorded evidence (e.g. a dataset cannot become ADMITTED without a referenced
admission report, and cannot become ACQUIRED before its terms of use were reviewed).
"""
from __future__ import annotations

import json
import datetime as _dt
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional

UNKNOWN = "UNKNOWN"

STATES = (
    "DISCOVERED",
    "ACCESS_PENDING",
    "LICENSE_VERIFIED",
    "ACQUIRED",
    "CONTENT_VERIFIED",
    "PROCESSED",
    "ADMITTED",
    "REJECTED",
    "BLOCKED",
)

LEGAL_TRANSITIONS: Dict[str, frozenset] = {
    "DISCOVERED": frozenset({"ACCESS_PENDING", "LICENSE_VERIFIED", "REJECTED", "BLOCKED"}),
    "ACCESS_PENDING": frozenset({"LICENSE_VERIFIED", "REJECTED", "BLOCKED"}),
    "LICENSE_VERIFIED": frozenset({"ACQUIRED", "ACCESS_PENDING", "REJECTED", "BLOCKED"}),
    "ACQUIRED": frozenset({"CONTENT_VERIFIED", "REJECTED", "BLOCKED"}),
    "CONTENT_VERIFIED": frozenset({"PROCESSED", "REJECTED", "BLOCKED"}),
    "PROCESSED": frozenset({"ADMITTED", "REJECTED", "CONTENT_VERIFIED"}),
    # Revocation or re-processing of an admitted dataset must itself be evidenced.
    "ADMITTED": frozenset({"REJECTED", "PROCESSED"}),
    # Re-evaluation requires new evidence and restarts the lifecycle.
    "REJECTED": frozenset({"DISCOVERED"}),
    "BLOCKED": frozenset({"DISCOVERED", "ACCESS_PENDING", "REJECTED"}),
}

# Source-research categories required by the Phase 8 specification (section 2.2).
ACCESS_CATEGORIES = (
    "VERIFIED_AVAILABLE",
    "ACADEMIC_ACCESS_REQUIRED",
    "LICENSE_UNCLEAR",
    "SOURCE_INACCESSIBLE",
    "INSUFFICIENT_EVIDENCE",
    "REJECTED",
)

RECORD_FIELDS = (
    "dataset_id", "name", "version", "publisher", "canonical_source", "access_method",
    "access_category", "license", "usage_restrictions", "collection_period",
    "publication_date", "acquisition_date", "raw_capture_available", "pcap_available",
    "labeling_methodology", "label_confidence", "composition", "malware_families",
    "network_environment", "os_environment", "protocol_coverage", "tls_version_coverage",
    "fingerprint_availability", "flow_count", "behavioral_group_count", "duplicate_statistics",
    "missingness_statistics", "provenance_completeness", "state", "exclusion_reasons",
    "reproducibility", "checksums", "processing_status", "research_role", "notes",
)


class RegistryError(ValueError):
    pass


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def new_record(dataset_id: str, name: str, **fields: Any) -> Dict[str, Any]:
    record: Dict[str, Any] = {f: UNKNOWN for f in RECORD_FIELDS}
    record.update({
        "dataset_id": dataset_id,
        "name": name,
        "state": "DISCOVERED",
        "exclusion_reasons": [],
        "checksums": {},
        "history": [],
    })
    for key, value in fields.items():
        if key not in RECORD_FIELDS:
            raise RegistryError(f"Unknown registry field '{key}'")
        record[key] = value
    if record["state"] not in STATES:
        raise RegistryError(f"Invalid initial state {record['state']}")
    record["history"].append({
        "from_state": None,
        "to_state": record["state"],
        "timestamp": _now(),
        "evidence": "Record created.",
        "evidence_refs": [],
        "actor": "registry",
    })
    return record


def _guard(record: Dict[str, Any], to_state: str, evidence_refs: List[str], context: Dict[str, Any]) -> None:
    """Raise RegistryError if the guard for `to_state` is not satisfied."""
    if to_state == "ACQUIRED":
        if record.get("license") in (None, "", UNKNOWN):
            raise RegistryError("ACQUIRED requires reviewed terms of use (license field is UNKNOWN).")
    if to_state == "CONTENT_VERIFIED":
        verified = context.get("verified_artifacts", 0)
        if verified < 1:
            raise RegistryError("CONTENT_VERIFIED requires at least one checksum-verified, parseable artifact.")
    if to_state == "PROCESSED":
        if not context.get("processing_record"):
            raise RegistryError("PROCESSED requires a processing record (script, version, output checksum).")
    if to_state == "ADMITTED":
        if not any(ref.endswith(("admission_report.json", "admission_report.md")) for ref in evidence_refs):
            raise RegistryError("ADMITTED requires a reference to an admission report.")
        if not context.get("admission_decision"):
            raise RegistryError("ADMITTED requires an explicit admission decision in the context.")
    if to_state == "REJECTED" and not context.get("reason"):
        raise RegistryError("REJECTED requires an explicit exclusion reason.")


def transition(record: Dict[str, Any], to_state: str, evidence: str,
               evidence_refs: Optional[List[str]] = None, actor: str = "pipeline",
               context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Apply one lifecycle transition. Returns the updated copy; never mutates the input."""
    if to_state not in STATES:
        raise RegistryError(f"Unknown state {to_state}")
    if not evidence or not evidence.strip():
        raise RegistryError("Every transition must carry a non-empty evidence statement.")
    current = record["state"]
    if to_state == current:
        return deepcopy(record)
    if to_state not in LEGAL_TRANSITIONS[current]:
        raise RegistryError(f"Illegal transition {current} -> {to_state} for {record['dataset_id']}")
    refs = list(evidence_refs or [])
    ctx = dict(context or {})
    _guard(record, to_state, refs, ctx)
    updated = deepcopy(record)
    updated["state"] = to_state
    if to_state == "REJECTED":
        updated["exclusion_reasons"] = list(updated.get("exclusion_reasons") or []) + [ctx["reason"]]
    updated["history"].append({
        "from_state": current,
        "to_state": to_state,
        "timestamp": _now(),
        "evidence": evidence,
        "evidence_refs": refs,
        "actor": actor,
    })
    return updated


def advance(record: Dict[str, Any], path: List[str], evidence: str,
            evidence_refs: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None,
            actor: str = "pipeline") -> Dict[str, Any]:
    """Apply a sequence of transitions, skipping states the record has already reached."""
    updated = record
    for state in path:
        if updated["state"] == state:
            continue
        updated = transition(updated, state, evidence, evidence_refs, actor=actor, context=context)
    return updated


class DatasetRegistry:
    """JSON-file backed registry. Writes are atomic (temp file + replace)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.records: Dict[str, Dict[str, Any]] = {}
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            for rec in data.get("datasets", []):
                self.records[rec["dataset_id"]] = rec

    def get(self, dataset_id: str) -> Optional[Dict[str, Any]]:
        return self.records.get(dataset_id)

    def all(self) -> List[Dict[str, Any]]:
        return [self.records[k] for k in sorted(self.records)]

    def upsert(self, record: Dict[str, Any]) -> None:
        if record["state"] not in STATES:
            raise RegistryError(f"Invalid state {record['state']}")
        self.records[record["dataset_id"]] = record

    def apply(self, dataset_id: str, to_state: str, evidence: str, **kwargs: Any) -> Dict[str, Any]:
        rec = self.records.get(dataset_id)
        if rec is None:
            raise RegistryError(f"Unknown dataset {dataset_id}")
        updated = transition(rec, to_state, evidence, **kwargs)
        self.records[dataset_id] = updated
        return updated

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "1.0",
            "generated_at": _now(),
            "states": list(STATES),
            "legal_transitions": {k: sorted(v) for k, v in LEGAL_TRANSITIONS.items()},
            "unknown_sentinel": UNKNOWN,
            "datasets": self.all(),
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)
