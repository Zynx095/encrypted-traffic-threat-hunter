"""
Deterministic corpus construction (Phase 8, corpus version v3).

Reuses the Phase 6 implementation unchanged in its semantics:
    FlowReconstructor (bidirectional 5-tuple flows, 120 s idle timeout, first-segment
    ClientHello/ServerHello parsing) and build_feature_record (behavioural features).

Additions relative to Stage 6.5 (v2):
    * capture-level provenance (capture_id, family_group, collection_date, environment)
      kept in a separate provenance table joined by corpus_index;
    * the frozen behavioral_hash grouping key is materialised once;
    * stored packet sequences are capped at MAX_PACKET_SEQUENCE_LENGTH (features are still
      computed on complete flows) and the original length is recorded;
    * fingerprint-integrity flag clienthello_record_truncated.

Raw captures are read-only. Interim per-capture flow tables are cached and keyed by the raw
SHA-256, which makes interrupted builds resumable.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dpkt
import numpy as np
import pandas as pd

from pipeline import config
from pipeline.corpus import paths
from pipeline.corpus.artifacts import ArtifactManifest
from pipeline.corpus.capture_plan import included, load_plan
from pipeline.corpus.extract import extract_member, mta_password, sha256_file
from pipeline.corpus.registry import UNKNOWN
from pipeline.corpus.validation import behavioral_hash_series, validate_pcap_file
from pipeline.feature_extraction import BURST_IDLE_THRESHOLD, build_feature_record
from pipeline.flow_reconstruction import DEFAULT_FLOW_IDLE_TIMEOUT, FlowReconstructor

logger = logging.getLogger(__name__)

CORPUS_VERSION = "v3"
BUILDER_VERSION = "8.0.0"
SEQUENCE_CAP = config.MAX_PACKET_SEQUENCE_LENGTH
SEQUENCE_COLUMNS = ["sequence_packet_lengths", "sequence_relative_times", "sequence_directions", "sequence_tcp_flags"]

# Columns produced by build_feature_record that identify provenance, never model input.
PROVENANCE_FROM_RECORD = ["flow_id", "dataset_id", "source_file", "label"]
EXTRA_INTERIM_COLUMNS = ["clienthello_record_truncated", "clienthello_parse_error", "protocol",
                         "forward_endpoint", "reverse_endpoint", "flow_instance"]


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def git_revision() -> str:
    try:
        rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=paths.PROJECT_ROOT, capture_output=True,
                             text=True, timeout=10).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=paths.PROJECT_ROOT,
                               capture_output=True, text=True, timeout=30).stdout.strip()
        return f"{rev}{'+dirty' if dirty else ''}" if rev else UNKNOWN
    except Exception:
        return UNKNOWN


# --------------------------------------------------------------------------- materialise --
def materialize(plan: Dict[str, Any], manifest: ArtifactManifest) -> List[Dict[str, Any]]:
    """Extract / locate every included capture and verify its bytes. Returns per-capture status."""
    results = []
    for cap in included(plan):
        container = cap["container"]
        raw_path = paths.resolve(cap["raw_path"])
        expected = None if cap["expected_sha256"] == UNKNOWN else cap["expected_sha256"]
        status, detail, digest, size = "MISSING", "", None, None

        if container["type"] == "zip":
            archive = paths.resolve(container["path"])
            if not archive.exists():
                status, detail = "MISSING", f"Source archive not present: {container['path']}"
            else:
                pwd = mta_password(container["post_date"]) if container.get("password_scheme") == "MTA_INFECTED_POST_DATE" else None
                res = extract_member(archive, container["member"], raw_path.parent, pwd, expected)
                digest, size, detail = res.sha256, res.size_bytes, res.detail
                status = {"EXTRACTED": "VERIFIED_CHECKSUM" if expected else "OBSERVED_AT_ACQUISITION",
                          "ALREADY_PRESENT": "VERIFIED_CHECKSUM" if expected else "OBSERVED_AT_ACQUISITION"}.get(res.status, res.status)
        else:
            if raw_path.exists():
                digest, size = sha256_file(raw_path), raw_path.stat().st_size
                if expected:
                    status = "VERIFIED_CHECKSUM" if digest == expected else "CHECKSUM_MISMATCH"
                else:
                    exp_size = cap.get("expected_size_bytes")
                    if isinstance(exp_size, int) and exp_size != size:
                        status, detail = "SIZE_MISMATCH", f"expected {exp_size} bytes, found {size}"
                    else:
                        status = "OBSERVED_AT_ACQUISITION"
                        detail = "No published checksum; SHA-256 recorded at first verification (trust-on-first-download)."
            else:
                status, detail = "MISSING", f"Raw file not present: {cap['raw_path']}"

        verification = {"status": status, "detail": detail, "expected_sha256": expected,
                        "expected_sha256_source": cap.get("expected_sha256_source"), "checked_at": _now()}
        manifest.record(
            f"RAW:{cap['capture_id']}", tier="RAW", dataset_id=cap["dataset_id"], capture_id=cap["capture_id"],
            path=cap["raw_path"], sha256=digest, size_bytes=size, source_url=cap.get("source_url"),
            acquisition=cap.get("acquisition"), label={"value": cap["label"], "derivation": cap["label_derivation"],
                                                        "granularity": cap["label_granularity"]},
            verification=verification,
            metadata={k: cap.get(k) for k in ("malware_family", "family_group", "collection_date", "environment", "os",
                                              "source_candidate_id", "prior_admission_status")},
        )
        results.append({"capture_id": cap["capture_id"], "dataset_id": cap["dataset_id"], "status": status,
                        "sha256": digest, "size_bytes": size, "detail": detail})
    return results


USABLE_RAW_STATUS = ("VERIFIED_CHECKSUM", "OBSERVED_AT_ACQUISITION")


# ------------------------------------------------------------------------- reconstruct --
def reconstruct_capture(pcap_path: Path, sha256: str) -> List[Dict[str, Any]]:
    recon = FlowReconstructor(pcap_sha256=sha256)
    with open(pcap_path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        reader = dpkt.pcapng.Reader(f) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(f)
        try:
            for ts, buf in reader:
                recon.process_packet(ts, buf)
        except (dpkt.NeedData, dpkt.UnpackError, ValueError) as exc:
            logger.warning("Capture %s ended with a truncated record: %s", pcap_path.name, exc)
    recon.flush_all()
    return recon.completed_flows


def _capped(seq: Any) -> Tuple[List[Any], int]:
    seq = list(seq.tolist() if hasattr(seq, "tolist") else (seq or []))
    return seq[:SEQUENCE_CAP], len(seq)


def features_for_capture(flows: List[Dict[str, Any]], cap: Dict[str, Any]) -> pd.DataFrame:
    records = []
    for i, flow in enumerate(flows):
        flow = dict(flow)
        flow["dataset_id"] = cap["dataset_id"]
        flow["source_file"] = Path(cap["raw_path"]).name
        rec = build_feature_record(flow)
        rec["label"] = cap["label"]              # capture-level label (build_feature_record only knows DS-004/DS-008)
        for col in EXTRA_INTERIM_COLUMNS:
            rec[col] = flow.get(col)
        for col in SEQUENCE_COLUMNS:
            rec[col], n = _capped(rec[col])
        rec["sequence_original_length"] = int(flow.get("packet_count", 0))
        rec["sequence_truncated"] = rec["sequence_original_length"] > SEQUENCE_CAP
        rec["capture_id"] = cap["capture_id"]
        rec["family_group"] = cap["family_group"]
        rec["malware_family"] = cap["malware_family"]
        rec["collection_date"] = cap["collection_date"]
        rec["environment"] = cap["environment"]
        rec["os"] = cap["os"]
        rec["capture_flow_index"] = i
        records.append(rec)
    return pd.DataFrame(records)


# Provenance / audit columns: never part of the model-candidate table.
PROVENANCE_COLUMNS = ["flow_id", "dataset_id", "source_file", "capture_id", "family_group", "malware_family",
                      "collection_date", "environment", "os", "capture_flow_index", "flow_instance",
                      "forward_endpoint", "reverse_endpoint", "clienthello_parse_error", "behavioral_hash"]


def build_corpus(plan_path: Path = paths.CAPTURE_PLAN_PATH, force: bool = False) -> Dict[str, Any]:
    plan = load_plan(plan_path)
    manifest = ArtifactManifest()
    materialized = materialize(plan, manifest)
    status_by_capture = {m["capture_id"]: m for m in materialized}

    validation = []
    frames = []
    flows_dir = paths.INTERIM_V3_DIR / "flows"
    flows_dir.mkdir(parents=True, exist_ok=True)

    for cap in included(plan):
        mat = status_by_capture[cap["capture_id"]]
        if mat["status"] not in USABLE_RAW_STATUS:
            validation.append({"capture_id": cap["capture_id"], "dataset_id": cap["dataset_id"],
                               "stage": "materialize", "status": mat["status"], "detail": mat["detail"]})
            continue
        raw = paths.resolve(cap["raw_path"])
        chk = validate_pcap_file(raw)
        validation.append({"capture_id": cap["capture_id"], "dataset_id": cap["dataset_id"], "stage": "pcap",
                           **chk.to_dict(), "path": cap["raw_path"]})
        if chk.status != "VALID":
            continue

        interim = flows_dir / f"{cap['capture_id']}.parquet"
        interim_meta = interim.with_suffix(".json")
        cached = (not force and interim.exists() and interim_meta.exists()
                  and json.loads(interim_meta.read_text())["raw_sha256"] == mat["sha256"])
        if cached:
            feat = pd.read_parquet(interim)
        else:
            logger.info("Reconstructing %s (%s)", cap["capture_id"], raw.name)
            flows = reconstruct_capture(raw, mat["sha256"])
            feat = features_for_capture(flows, cap)
            feat.to_parquet(interim, index=False)
            interim_meta.write_text(json.dumps({"raw_sha256": mat["sha256"], "flows": len(feat),
                                                "builder_version": BUILDER_VERSION, "built_at": _now()}, indent=2))
        manifest.record(f"INTERIM:{cap['capture_id']}", tier="INTERIM", dataset_id=cap["dataset_id"],
                        capture_id=cap["capture_id"], path=paths.rel(interim), sha256=sha256_file(interim),
                        size_bytes=interim.stat().st_size, derived_from=[f"RAW:{cap['capture_id']}"],
                        processing={"script": "pipeline.corpus.builder.features_for_capture",
                                    "builder_version": BUILDER_VERSION,
                                    "config": {"flow_idle_timeout_s": DEFAULT_FLOW_IDLE_TIMEOUT,
                                               "burst_idle_threshold_s": BURST_IDLE_THRESHOLD,
                                               "sequence_cap": SEQUENCE_CAP}},
                        verification={"status": "PASSED", "flows": int(len(feat))})
        frames.append(feat)

    if not frames:
        manifest.save()
        raise RuntimeError("No capture could be materialised and validated; corpus not built.")

    corpus = pd.concat(frames, ignore_index=True)
    corpus = corpus.sort_values(["capture_id", "capture_flow_index"], kind="mergesort").reset_index(drop=True)
    corpus.insert(0, "corpus_index", np.arange(len(corpus), dtype=np.int64))

    non_feature = set(PROVENANCE_COLUMNS) | set(SEQUENCE_COLUMNS) | {"corpus_index", "label",
                                                                    "sequence_original_length", "sequence_truncated",
                                                                    "clienthello_record_truncated", "protocol"}
    flat_feature_cols = [c for c in corpus.columns if c not in non_feature]
    corpus["behavioral_hash"] = behavioral_hash_series(corpus, flat_feature_cols)

    prov_cols = ["corpus_index", "label"] + [c for c in PROVENANCE_COLUMNS if c in corpus.columns]
    provenance = corpus[prov_cols].copy()
    model_cols = [c for c in corpus.columns if c not in set(PROVENANCE_COLUMNS) or c == "behavioral_hash"]
    model_cols = [c for c in model_cols if c not in ("flow_id", "dataset_id", "source_file", "behavioral_hash")]
    flows = corpus[model_cols].copy()

    paths.PROCESSED_V3_DIR.mkdir(parents=True, exist_ok=True)
    flows.to_parquet(paths.CORPUS_FEATURES_PATH, index=False)
    provenance.to_parquet(paths.CORPUS_PROVENANCE_PATH, index=False)

    out_hashes = {paths.rel(paths.CORPUS_FEATURES_PATH): sha256_file(paths.CORPUS_FEATURES_PATH),
                  paths.rel(paths.CORPUS_PROVENANCE_PATH): sha256_file(paths.CORPUS_PROVENANCE_PATH)}
    for p, h in out_hashes.items():
        manifest.record(f"PROCESSED:{Path(p).name}", tier="PROCESSED", dataset_id="CORPUS", path=p, sha256=h,
                        size_bytes=paths.resolve(p).stat().st_size,
                        derived_from=[f"INTERIM:{c}" for c in sorted(corpus["capture_id"].unique())],
                        processing={"script": "pipeline.corpus.builder.build_corpus", "builder_version": BUILDER_VERSION},
                        verification={"status": "PASSED", "rows": int(len(corpus))})
    manifest.save()

    corpus_manifest = {
        "corpus_version": CORPUS_VERSION,
        "builder_version": BUILDER_VERSION,
        "pipeline_version": config.PIPELINE_VERSION,
        "built_at": _now(),
        "source_revision": git_revision(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "dependencies": {"dpkt": getattr(dpkt, "__version__", UNKNOWN), "pandas": pd.__version__, "numpy": np.__version__},
        "config": {"flow_idle_timeout_s": DEFAULT_FLOW_IDLE_TIMEOUT, "burst_idle_threshold_s": BURST_IDLE_THRESHOLD,
                   "sequence_cap": SEQUENCE_CAP},
        "inputs": {m["capture_id"]: {"sha256": m["sha256"], "status": m["status"]} for m in materialized},
        "outputs": out_hashes,
        "rows": int(len(corpus)),
        "captures_built": sorted(corpus["capture_id"].unique().tolist()),
        "flat_feature_columns": flat_feature_cols,
        "behavioral_hash_definition": "sha256(str(sorted((col, val) for non-null flat feature columns))) — identical to ExperimentConstructor.hash_row",
        "label_counts": {str(k): int(v) for k, v in corpus["label"].value_counts().items()},
    }
    paths.CORPUS_MANIFEST_PATH.write_text(json.dumps(corpus_manifest, indent=2), encoding="utf-8")
    paths.VALIDATION_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    paths.VALIDATION_REPORT_PATH.write_text(json.dumps({"generated_at": _now(), "materialize": materialized,
                                                        "checks": validation}, indent=2, default=str), encoding="utf-8")
    return corpus_manifest


def load_corpus() -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Return (model-candidate table, provenance table)."""
    if not paths.CORPUS_FEATURES_PATH.exists():
        raise FileNotFoundError(f"Corpus not built: {paths.rel(paths.CORPUS_FEATURES_PATH)}")
    return pd.read_parquet(paths.CORPUS_FEATURES_PATH), pd.read_parquet(paths.CORPUS_PROVENANCE_PATH)
