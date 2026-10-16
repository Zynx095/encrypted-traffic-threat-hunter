"""
Corpus validation: PCAP integrity and flow-level duplicate / leakage diagnostics.

Terminology (documented in PHASE_8_BENIGN_CORPUS.md):
  exact duplicate flow     -- two flows whose full feature vector AND packet sequences are identical;
  behavioural duplicate    -- flows sharing a behavioral_hash (identical flat feature vector,
                              the frozen Phase 7 grouping key); sequences may differ in timing;
  legitimate repetition    -- behavioural duplicates produced by the sampling process itself
                              (beaconing, retries). They are kept and grouped, never deleted,
                              because removing them would change the observed traffic population.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import dpkt
import numpy as np
import pandas as pd

SUPPORTED_LINKTYPES = {1: "EN10MB", 101: "RAW", 12: "RAW_BSD", 113: "LINUX_SLL", 228: "IPV4", 229: "IPV6"}
PCAP_MAGICS = {b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


@dataclass
class PcapCheck:
    path: str
    status: str                      # VALID | INVALID | UNSUPPORTED | MISSING
    format: Optional[str] = None
    linktype: Optional[int] = None
    linktype_name: Optional[str] = None
    snaplen: Optional[int] = None
    packet_count: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    non_monotonic_timestamps: int = 0
    zero_length_frames: int = 0
    parse_error_after_packets: Optional[int] = None
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def validate_pcap_file(path: Path) -> PcapCheck:
    path = Path(path)
    chk = PcapCheck(path=str(path), status="VALID")
    if not path.exists():
        chk.status = "MISSING"
        chk.issues.append("file not found")
        return chk
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        try:
            if magic == PCAPNG_MAGIC:
                reader = dpkt.pcapng.Reader(f)
                chk.format = "pcapng"
            elif magic in PCAP_MAGICS:
                reader = dpkt.pcap.Reader(f)
                chk.format = "pcap"
                chk.snaplen = int(getattr(reader, "snaplen", 0)) or None
            else:
                chk.status = "INVALID"
                chk.issues.append(f"unknown magic bytes {magic.hex()}")
                return chk
        except Exception as exc:  # malformed header
            chk.status = "INVALID"
            chk.issues.append(f"header parse failure: {exc}")
            return chk

        chk.linktype = int(reader.datalink())
        chk.linktype_name = SUPPORTED_LINKTYPES.get(chk.linktype)
        if chk.linktype_name is None:
            chk.status = "UNSUPPORTED"
            chk.issues.append(f"unsupported link type {chk.linktype}")

        prev = None
        try:
            for ts, buf in reader:
                chk.packet_count += 1
                if chk.first_ts is None:
                    chk.first_ts = float(ts)
                chk.last_ts = float(ts)
                if prev is not None and ts < prev:
                    chk.non_monotonic_timestamps += 1
                prev = ts
                if len(buf) == 0:
                    chk.zero_length_frames += 1
        except Exception as exc:
            chk.parse_error_after_packets = chk.packet_count
            chk.issues.append(f"truncated or corrupt record after {chk.packet_count} packets: {exc}")
            if chk.packet_count == 0:
                chk.status = "INVALID"

    if chk.packet_count == 0 and chk.status == "VALID":
        chk.status = "INVALID"
        chk.issues.append("no packets")
    if chk.snaplen is not None and chk.snaplen < 1600:
        chk.issues.append(f"snaplen {chk.snaplen} < 1600: TLS handshakes may be cut")
    if chk.non_monotonic_timestamps:
        chk.issues.append(f"{chk.non_monotonic_timestamps} non-monotonic timestamps")
    return chk


def duplicate_files(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Captures whose raw bytes are identical (same SHA-256)."""
    by_hash: Dict[str, List[str]] = {}
    for e in entries:
        if e.get("sha256"):
            by_hash.setdefault(e["sha256"], []).append(e.get("capture_id") or e["artifact_id"])
    return [{"sha256": h, "captures": c} for h, c in by_hash.items() if len(c) > 1]


def behavioral_hash_series(df: pd.DataFrame, feature_cols: List[str]) -> pd.Series:
    """
    Frozen Phase 7 grouping key: SHA-256 of the sorted (column, value) pairs of the non-null
    flat features, identical to ExperimentConstructor.hash_row.
    """
    def hash_row(row):
        row_dict = {k: v for k, v in row.items() if pd.notnull(v)}
        return hashlib.sha256(str(sorted(row_dict.items())).encode()).hexdigest()
    return df[feature_cols].apply(hash_row, axis=1)


def exact_duplicate_mask(df: pd.DataFrame, feature_cols: List[str], sequence_cols: List[str]) -> pd.Series:
    def seq_key(row):
        return hashlib.sha256(repr([list(row[c]) if row[c] is not None else None for c in sequence_cols]).encode()).hexdigest()
    keyed = df[feature_cols].copy()
    if sequence_cols:
        keyed["__seq__"] = df[sequence_cols].apply(seq_key, axis=1)
    return keyed.astype(str).duplicated(keep=False)


def duplicate_diagnostics(df: pd.DataFrame, group_col: str = "behavioral_hash",
                          capture_col: str = "capture_id", dataset_col: str = "dataset_id",
                          label_col: str = "label") -> Dict[str, Any]:
    sizes = df.groupby(group_col).size()
    dup_groups = sizes[sizes > 1]
    in_dup = df[df[group_col].isin(dup_groups.index)]
    def spans(col):
        if in_dup.empty:
            return 0
        return int((in_dup.groupby(group_col)[col].nunique() > 1).sum())
    return {
        "flows": int(len(df)),
        "behavioral_groups": int(sizes.size),
        "singleton_groups": int((sizes == 1).sum()),
        "duplicate_groups": int(dup_groups.size),
        "flows_in_duplicate_groups": int(len(in_dup)),
        "largest_group_size": int(sizes.max()) if sizes.size else 0,
        "behavioral_duplicate_rate": round(float(len(in_dup)) / max(len(df), 1), 6),
        "cross_capture_groups": spans(capture_col),
        "cross_dataset_groups": spans(dataset_col),
        "cross_label_groups": spans(label_col),
    }


def missingness_table(df: pd.DataFrame, cols: List[str], by: Optional[str] = None) -> Dict[str, Any]:
    if by is None:
        return {c: round(float(df[c].isna().mean()), 6) for c in cols}
    out: Dict[str, Any] = {}
    for key, part in df.groupby(by):
        out[str(key)] = {c: round(float(part[c].isna().mean()), 6) for c in cols}
    return out


def tls_coverage(df: pd.DataFrame, by: Optional[str] = None) -> Dict[str, Any]:
    def summarize(part: pd.DataFrame) -> Dict[str, Any]:
        n = len(part)
        ja3 = part["ja3_hash"].notna()
        ja4 = part["ja4"].notna()
        ch = part["clienthello_present"].fillna(False).astype(bool)
        sh = part["serverhello_present"].fillna(False).astype(bool)
        tcp443 = part["protocol"].eq("TCP") if "protocol" in part else pd.Series(False, index=part.index)
        out = {
            "flows": int(n),
            "tcp_flows": int(tcp443.sum()) if "protocol" in part else None,
            "clienthello_flows": int(ch.sum()),
            "serverhello_flows": int(sh.sum()),
            "ja3_available": int(ja3.sum()),
            "ja4_available": int(ja4.sum()),
            "ja3s_available": int(part["ja3s_hash"].notna().sum()),
            "both_ja3_ja4": int((ja3 & ja4).sum()),
            "neither_ja3_ja4": int((~ja3 & ~ja4).sum()),
            "ja3_coverage": round(float(ja3.mean()), 6) if n else None,
            "ja4_coverage": round(float(ja4.mean()), 6) if n else None,
            "tls_version_counts": {str(k): int(v) for k, v in part["tls_version"].value_counts(dropna=False).items()},
        }
        if "clienthello_record_truncated" in part:
            trunc = part["clienthello_record_truncated"].fillna(False).astype(bool)
            out["clienthello_truncated_in_first_segment"] = int(trunc.sum())
            out["fingerprints_from_truncated_clienthello"] = int((trunc & ja3).sum())
        return out
    if by is None:
        return summarize(df)
    return {str(k): summarize(p) for k, p in df.groupby(by)}


def label_conflicts(df: pd.DataFrame, group_col: str = "behavioral_hash", label_col: str = "label") -> List[str]:
    """Behavioural groups that carry more than one binary label (benign vs malicious)."""
    binary = df[label_col].map(lambda x: "MALICIOUS" if "MALICIOUS" in str(x).upper() else "BENIGN")
    tmp = pd.DataFrame({group_col: df[group_col], "y": binary})
    conflicted = tmp.groupby(group_col)["y"].nunique()
    return conflicted[conflicted > 1].index.tolist()


def fingerprint_overlap(df: pd.DataFrame, col: str, label_col: str = "label") -> Dict[str, Any]:
    """How many fingerprint values occur in both classes (shared client stacks)."""
    y = df[label_col].map(lambda x: 1 if "MALICIOUS" in str(x).upper() else 0)
    sub = pd.DataFrame({"fp": df[col], "y": y}).dropna()
    per = sub.groupby("fp")["y"].agg(["min", "max", "size"])
    shared = per[(per["min"] == 0) & (per["max"] == 1)]
    return {
        "distinct_values": int(per.shape[0]),
        "distinct_malicious_only": int(((per["min"] == 1)).sum()),
        "distinct_benign_only": int(((per["max"] == 0)).sum()),
        "distinct_shared": int(shared.shape[0]),
        "flows_with_shared_values": int(sub[sub["fp"].isin(shared.index)].shape[0]),
    }
