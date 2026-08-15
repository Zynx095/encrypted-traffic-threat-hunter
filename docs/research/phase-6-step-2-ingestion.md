# Phase 6 Step 2 â€” Dataset Ingestion

## 1. Objective
Build the foundation for dataset ingestion and PCAP validation. This step ensures that before any packet or flow analysis occurs, the raw PCAP files are discovered, hashed for provenance, validated for readabililty, and registered with dataset-specific metadata.

## 2. Architecture Implemented
A modular pipeline was constructed in `pipeline/` per the Phase 6 architecture:
- **`config.py`**: Centralized, machine-independent configuration using relative paths.
- **`hashing.py`**: Deterministic SHA-256 for immutable tracking.
- **`pcap_validator.py`**: Validation via `dpkt`, enforcing the rejection of unsupported formats (e.g. `pcapng`) and catching corrupt/empty files.
- **`manifest.py`**: Generation of CSV and JSON manifests to track ingestion status.
- **`adapters/base.py`**: Common abstract interface for heterogeneous datasets.
- **`ingestion.py`**: Orchestrator that bridges dataset adapters with validation and manifest writing.

## 3. Dataset Adapters
- **DS-008 (Malware-Traffic-Analysis)**: Scans for PCAPs. Extracts malware family and capture date from filename conventions. Normalizes all labels to `MALICIOUS`.
- **DS-004 (CipherSpectrum)**: Scans for PCAPs. Prepares infrastructure for future application-label ingestion and normalizes to `BENIGN_VALIDATION`.
- **DS-006 & DS-007 (Brno Datasets)**: Stubbed adapters representing future academic access, safely returning `NOT_IMPLEMENTED`.

## 4. Manifest Format
Ingestion outputs both CSV and JSON formats to `data/manifests/` holding 16 fields covering: `dataset_id`, `dataset_name`, `source_file`, `relative_path`, `file_size_bytes`, `sha256`, `format`, `packet_count`, `validation_status`, `validation_reason`, `malware_family`, `original_label`, `research_role`, `ingestion_status`, `pipeline_version`, and `ingestion_timestamp`.

## 5. PCAP Validation
Validation checks for magic bytes (`\xd4\xc3\xb2\xa1` etc.) and uses `dpkt` to quickly parse the file without executing its contents. Files are flagged as `VALID`, `INVALID`, or `UNSUPPORTED`. Corrupt files log a `validation_reason` without halting the pipeline.

## 6. Provenance
Every ingested record is tightly coupled to the dataset ID, original source file name, and SHA-256 checksum. A `pipeline_version` tracks exactly what extraction code parsed it.

## 7. Reproducibility
Hardcoded paths were avoided. `config.py` infers `PROJECT_ROOT` automatically based on file location. Missing files or skipped records are logged rather than silently dropped, guaranteeing consistent deterministic manifests on any host.

## 8. Safety
The validator reads network files only at the packet envelope layer using pure Python `dpkt`. Content payloads are strictly untouched, guaranteeing that malicious active payloads will not execute.

## 9. Tests
Unit tests in `tests/test_ingestion.py` cover:
- Cryptographic hashing consistency.
- Correct rejection of missing or corrupt PCAPs.
- Explicit `UNSUPPORTED` tagging for `pcapng`.
- Metadata extraction precision for DS-008 and DS-004.
All tests passed.

## 10. Known Limitations
- The `pcapng` format is not natively supported by `dpkt` and is correctly flagged as unsupported during validation. Future processing of `.pcapng` files requires either external conversion to `.pcap` or integrating Scapy exclusively for those files.
- The DS-004 adapter assumes a single application label per PCAP or directory, to be expanded once full dataset CSVs are integrated.

## 11. Phase 3 Dependencies
This ingestion foundation outputs an INTERIM record layout that feeds directly into flow reconstruction (Step 3).

## 12. Open Issues
- None at this step. Ready for flow reconstruction.
