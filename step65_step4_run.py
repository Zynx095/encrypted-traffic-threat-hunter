import os
import csv
import glob
import logging
import hashlib
from pathlib import Path
import dpkt
import pandas as pd
from typing import List, Dict, Any

from pipeline.flow_reconstruction import FlowReconstructor
from pipeline.feature_extraction import build_feature_record
from pipeline.model_safe_generator import generate_model_safe_split
from pipeline.experimental_dataset_constructor import ExperimentConstructor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def process_pcaps():
    v2_interim = Path("data/interim/v2")
    v2_interim_flows = v2_interim / "flows"
    v2_processed = Path("data/processed/v2")
    v2_features = v2_processed / "features"
    v2_model_safe = v2_processed / "model_safe"
    v2_experiments = v2_processed / "experiments"
    v2_manifests = Path("data/manifests/v2")

    for d in [v2_interim_flows, v2_features, v2_model_safe, v2_experiments, v2_manifests]:
        d.mkdir(parents=True, exist_ok=True)

    # Get DS004 PCAPs
    ds004_pcaps = list(Path("data/samples/ds004").rglob("*.pcap"))

    # Get expanded DS-008 PCAPs from manifest
    ds008_pcaps = []
    manifest_path = "data/manifests/ds008_expanded_corpus_manifest.csv"
    with open(manifest_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["admission_status"] == "ADMITTED" or row["admission_status"] == "CURRENT VERIFIED BASELINE":
                fname = row["pcap_filename"]
                if row["admission_status"] == "CURRENT VERIFIED BASELINE":
                    # They are in data/verification/pcaps
                    p = Path("data/verification/pcaps") / fname
                else:
                    # They are in data/verification/mta_stage65
                    p = Path("data/verification/mta_stage65") / fname
                if p.exists():
                    ds008_pcaps.append((p, row))
                else:
                    logger.error(f"Missing PCAP {p}")

    all_flows = []

    def run_reconstruction(pcap_path, label_meta):
        sha256 = compute_sha256(pcap_path)
        reconstructor = FlowReconstructor(pcap_sha256=sha256)

        try:
            with open(pcap_path, 'rb') as f:
                if pcap_path.name.endswith(".pcapng"):
                    reader = dpkt.pcapng.Reader(f)
                else:
                    reader = dpkt.pcap.Reader(f)

                for ts, buf in reader:
                    reconstructor.process_packet(ts, buf)
            reconstructor.flush_all()
        except Exception as e:
            logger.error(f"Error parsing {pcap_path}: {e}")

        flows = []
        for d in reconstructor.completed_flows:
            # Add metadata
            d["dataset_id"] = label_meta.get("dataset_id", "DS-008")
            d["corpus_sample_id"] = label_meta.get("corpus_sample_id", "")
            d["mta_candidate_id"] = label_meta.get("mta_candidate_id", "")
            d["source_file"] = pcap_path.name
            d["malware_family"] = label_meta.get("malware_family", "UNKNOWN")
            d["label"] = label_meta.get("label", "MALICIOUS")
            flows.append(d)

        logger.info(f"Reconstructed {len(flows)} flows from {pcap_path.name}")
        return flows, sha256

    # Process DS004
    for p in ds004_pcaps:
        label_meta = {
            "dataset_id": "DS-004",
            "label": "BENIGN_VALIDATION",
            "malware_family": "BENIGN"
        }
        flows, sha256 = run_reconstruction(p, label_meta)
        all_flows.extend(flows)

    # Process DS008
    for p, row in ds008_pcaps:
        label_meta = {
            "dataset_id": "DS-008",
            "corpus_sample_id": row["corpus_sample_id"],
            "mta_candidate_id": row["mta_candidate_id"],
            "label": "MALICIOUS",
            "malware_family": row["malware_family"]
        }
        flows, sha256 = run_reconstruction(p, label_meta)
        all_flows.extend(flows)

    # Save raw flows
    flows_df = pd.DataFrame(all_flows)
    flows_out = v2_interim_flows / "all_flows.parquet"
    flows_df.to_parquet(flows_out, index=False)

    # Feature Extraction
    logger.info("Running feature extraction...")
    feature_records = []
    for _, row in flows_df.iterrows():
        record = build_feature_record(row.to_dict())
        # Restore metadata missing from build_feature_record
        for k in ["dataset_id", "corpus_sample_id", "mta_candidate_id", "source_file", "malware_family", "label", "pcap_sha256"]:
            if k in row:
                record[k] = row[k]
        feature_records.append(record)

    features_df = pd.DataFrame(feature_records)
    features_out = v2_features / "flows_behavioral_features.parquet"
    features_df.to_parquet(features_out, index=False)
    logger.info(f"Extracted {len(features_df)} feature rows")

    # Model-Safe Generation
    logger.info("Generating model safe split...")
    model_safe_df, provenance_df, drop_stats = generate_model_safe_split(features_df)

    model_safe_out = v2_model_safe / "model_safe_dataset.parquet"
    provenance_out = v2_model_safe / "provenance_metadata.parquet"
    model_safe_df.to_parquet(model_safe_out, index=False)
    provenance_df.to_parquet(provenance_out, index=False)

    logger.info(f"Model safe rows: {len(model_safe_df)}")

    # Experimental Dataset Constructor
    logger.info("Constructing Experimental Datasets...")
    constructor = ExperimentConstructor(model_safe_df, provenance_df)
    dup_stats = constructor.analyze_duplicates()

    logger.info(f"Duplicates: groups={dup_stats['duplicate_groups']}, cross_pcap={dup_stats['cross_pcap_duplicate_groups']}, cross_label={dup_stats['cross_label_duplicate_groups']}")

    A, A_meta = constructor.generate_experiment_A()
    B, B_meta = constructor.generate_experiment_B()
    C, C_meta = constructor.generate_experiment_C()
    D, D_meta = constructor.generate_experiment_D()
    E, E_meta = constructor.generate_experiment_E()

    A.to_parquet(v2_experiments / "A_flow_only.parquet", index=False)
    A_meta.to_parquet(v2_experiments / "A_flow_only_meta.parquet", index=False)
    B.to_parquet(v2_experiments / "B_ja3_only.parquet", index=False)
    B_meta.to_parquet(v2_experiments / "B_ja3_only_meta.parquet", index=False)
    C.to_parquet(v2_experiments / "C_ja4_only.parquet", index=False)
    C_meta.to_parquet(v2_experiments / "C_ja4_only_meta.parquet", index=False)
    D.to_parquet(v2_experiments / "D_ja3_flow.parquet", index=False)
    D_meta.to_parquet(v2_experiments / "D_ja3_flow_meta.parquet", index=False)
    E.to_parquet(v2_experiments / "E_ja4_flow.parquet", index=False)
    E_meta.to_parquet(v2_experiments / "E_ja4_flow_meta.parquet", index=False)

    # Write Audit JSON
    import json
    audit_info = {
        "flows_total": len(flows_df),
        "tls_flows": len(features_df[features_df["tls_version"].notnull()]),
        "tls12_flows": len(features_df[features_df["tls_version"] == 1.2]),
        "tls13_flows": len(features_df[features_df["tls_version"] == 1.3]),
        "ja3_flows": len(features_df[features_df["ja3_hash"].notnull() & (features_df["ja3_hash"] != "")]),
        "ja3s_flows": len(features_df[features_df["ja3s_hash"].notnull() & (features_df["ja3s_hash"] != "")]),
        "ja4_flows": len(features_df[features_df["ja4"].notnull() & (features_df["ja4"] != "")]),
        "behavioral_feature_rows": len(features_df),
        "model_safe_rows": len(model_safe_df),
        "experiment_A_rows": len(A),
        "experiment_B_rows": len(B),
        "experiment_C_rows": len(C),
        "experiment_D_rows": len(D),
        "experiment_E_rows": len(E),
        "duplicates": dup_stats,
        "ds008_flows": len(features_df[features_df["dataset_id"] == "DS-008"]),
        "ds004_flows": len(features_df[features_df["dataset_id"] == "DS-004"])
    }

    with open(v2_manifests / "phase6_expanded_audit.json", "w") as f:
        json.dump(audit_info, f, indent=2)

    print(json.dumps(audit_info, indent=2))

if __name__ == "__main__":
    process_pcaps()
