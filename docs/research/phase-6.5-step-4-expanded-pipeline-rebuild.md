# Phase 6.5 Step 4 — Expanded Pipeline Rebuild

## 1. Objective
Rebuild the Phase 6 ingestion and feature pipeline using the existing DS-004 benign validation samples and the newly approved 10-sample DS-008 malicious corpus. Produce a versioned (`v2`) dataset output for the expanded corpus while preserving the original Phase 6 outputs.

## 2. Corpus Used
- **DS-008 (Malware-Traffic-Analysis.net)**: 10 PCAPs explicitly approved in Phase 6.5 Step 3.
- **DS-004 (CipherSpectrum)**: 6 PCAPs (Existing benign validation baseline).

## 3. Pipeline Configuration
The pipeline utilized the exact same Phase 6 implementations for:
- PCAP Validation (`pipeline/pcap_validator.py`)
- Flow Reconstruction (`pipeline/flow_reconstruction.py`)
- TLS Fingerprinting (`pipeline/tls_fingerprinting.py`)
- Feature Extraction (`pipeline/feature_extraction.py`)
- Model-Safe Generation (`pipeline/model_safe_generator.py`)
- Experimental Dataset Construction (`pipeline/experimental_dataset_constructor.py`)

No modifications were made to the core pipeline modules. A wrapper script (`step65_step4_run.py`) was used to iterate the validated corpus, explicitly pointing the outputs to the new `v2` directory schema (`data/interim/v2/`, `data/processed/v2/`, `data/manifests/v2/`).

## 4. Pipeline Execution Summary

### Flow Reconstruction
- **Total reconstructed flows:** 2,549 (Expanded from 1,460 in original Phase 6)
- **DS-008 Flows:** 2,543 (Expanded from 1,454)
- **DS-004 Flows:** 6 (Unchanged)

### TLS Extraction
- **Total TLS flows:** 200
- **TLS 1.2 flows:** 113
- **TLS 1.3 flows:** 87
- **JA3 flows:** 200
- **JA3S flows:** 202
- **JA4 flows:** 200 (Expanded from 62)

The 200 JA4 fingerprints validate the empirical quality of the new DS-008 corpus.

### Behavioral Feature Generation
- **Behavioral Feature Rows:** 2,549

### Model-Safe Generation
- **Model-Safe Rows:** 2,549

### Experimental Datasets (A–E)
- **Experiment A (Flow-only):** 2,068 rows
- **Experiment B (JA3-only):** 160 rows
- **Experiment C (JA4-only):** 160 rows
- **Experiment D (JA3 + Flow):** 160 rows
- **Experiment E (JA4 + Flow):** 160 rows

The rows for B-E are filtered by the availability of a fingerprint.

## 5. Duplicate Analysis
- **Exact duplicate behavior hashes:** 1,005
- **Duplicate groups:** 75
- **Cross-PCAP duplicate groups:** 0
- **Cross-label duplicate groups:** 0

As expected for sandbox executions, we see significant behavioral duplication (1,005 exact duplicate rows mapped into 75 groups) likely representing repeated polling mechanisms within single malware samples. Crucially, there are NO cross-label duplicates. The absence of cross-pcap duplicates suggests that the different malware captures in the expanded DS-008 do not produce identical behavioral telemetry.

## 6. Leakage Analysis
The `model_safe_dataset` schema ensures strict leakage control.
- **IP / Ports / MACs:** Omitted.
- **Absolute timestamps:** Omitted.
- **Identifiers / Filenames:** Extracted to the separate `provenance_metadata.parquet` file and completely omitted from `model_safe_dataset.parquet`.
- **Benign Class Distribution Limitation:** Since DS-004 currently only consists of 6 validation flows, it is inadequate for proper model training. Phase 7 considerations must address acquiring or configuring a realistic DS-004-scale benign background traffic dataset.
- **Source Artifacts Risk:** Given that all malicious samples (DS-008) arise from the Malware-Traffic-Analysis.net source, we remain vulnerable to source-specific capture characteristics (e.g. constant MTA packet-length quirks) which model experiments must be wary of.

## 7. Class Balance
**DS-008 (MALICIOUS):** 2,543 rows
**DS-004 (BENIGN_VALIDATION):** 6 rows

The corpus is highly imbalanced in favor of MALICIOUS flows, reflecting the current state of dataset expansion. We have adhered strictly to the instruction to avoid synthetic rebalancing (SMOTE) or duplication in Phase 6.

## 8. Comparison with Original Phase 6

| Metric | Original Phase 6 | Expanded Phase 6 |
| :--- | :--- | :--- |
| **DS-008 PCAPs** | 2 | 10 |
| **Total Flows** | 1,460 | 2,549 |
| **JA4 Flows** | 62 | 200 |

## 9. Reproducibility
- **Pipeline Config Version:** 0.1.0
- **Python Version:** 3.12
- **Audit File:** `data/manifests/v2/phase6_expanded_audit.json`

## 10. Conclusion
The Phase 6 expanded rebuild was successful. 2,549 bidirectional flows were successfully processed across 10 distinct malware captures, generating 200 TLS fingerprints and producing the versioned experimental datasets. No legacy outputs were harmed, and the `v2` outputs provide a robust foundation for next steps.

---

**Step 4 Status:** COMPLETE
