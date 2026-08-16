# Phase 6 Step 7 — Leakage-Controlled Model-Safe Dataset

## 1. Purpose
This step formally converts the raw behavioral features array constructed in Step 6 into a rigorously evaluated, leakage-controlled MODEL-SAFE format. The objective is to proactively eliminate environment identifiability, dataset provenance signatures, and host/capture memorization vectors before exposing features to ML mechanisms.

## 2. Input Dataset
The input is the processed output from Step 6 (`data/processed/features/flows_behavioral_features.parquet`), containing approximately 1,460 reconstructed flows encompassing metadata, timing profiles, sizing signatures, and embedded raw TLS configurations.

## 3. Model-Safe Definition
A dataset is deemed "MODEL-SAFE" when it strictly adheres to the experimental design methodology bounding feature accessibility. Model-safe means the algorithm receives absolutely zero explicit deterministic routing data (IP/Port), zero deterministic host/environment identification (MAC/SNI domain/Timestamps), and zero dataset origin mapping (`dataset_id`). It relies entirely upon abstract behavioral geometry.

## 4. Forbidden Features (Explicitly Stripped)
The implementation statically intercepts and annihilates any columns containing the following properties or matching the following substring masks (exceptions detailed in bounds):
- IP addresses (`src_ip`, `dst_ip`, etc.)
- Ports (`src_port`, `dst_port`)
- MAC Addresses
- Datetimes / Time (Epoch timestamps, Wall-clock time)
- Dates (Year, Month, Weekday)
- Raw TLS SNI domain strings (`sni_domain`, `server_name`)
- Origin hashes (`flow_id`)
- Source identifiers (`dataset_id`, `source_file`, `capture_environment`)

## 5. Allowed Feature Families
- **Flow Statistics:** Abstract size and temporal volume measurements (e.g. `flow_duration`, `total_packets`, ratios, directional metrics).
- **Temporal Vectors:** Abstract IAT (Inter-Arrival-Time) statistics measuring flow cadence independently of absolute clock constraints.
- **Size Vectors:** Directional lengths measuring flow density independently of protocol definitions.
- **TLS Bounds:** Extracted configuration states (`tls_version`, `sni_present`, TLS array sizes, JA3/JA4 cryptographic structural hashes).
- **Sequence Preservation:** Raw arrays of packet lengths, relative times, and direction indicators (`sequence_packet_lengths`, etc.) remain for advanced models explicitly requiring unflattened architectures.

## 6. Label Handling
Labels (`MALICIOUS`, `BENIGN_VALIDATION`) are natively maintained natively in the `label` column alongside model-safe features. They remain strictly partitioned conceptually as "targets" (not features).

## 7. Missing-Value Handling
Semantic missingness remains explicitly encoded as `np.nan` (or `None`). The framework rejects blanket zero-imputation; an absent TLS parameter due to a missing ClientHello structure is categorically distinct from a numerical zero representation. Imputation must occur during explicit modeling phases.

## 8. Provenance Separation
To maintain rigorous auditability without poisoning the ML matrices, the pipeline diverges into two parallel architectures linked securely via a `model_safe_index`:
- `data/processed/model_safe/flows_model_safe.parquet`: Strict feature bounds.
- `data/processed/model_safe/flows_provenance.parquet`: Contains strict metadata mappings (e.g., origin files, exact source identifiers, tracking hashes).

## 9. Duplicate Checks
Deterministic hashing identified 553 duplicate feature vectors across the 1460 processed rows. These duplicate structures highlight automated repetition in malware behavior, potential internal replication artifacts, or persistent constant-traffic characteristics. No aggressive deduplication is applied prior to standard experimental splitting.

## 10. Dataset-Source Leakage Audit
Missingness alignment between datasets was verified computationally via `step7_validation.py`. No single feature missingness profile perfectly split the target populations of DS-008 (`MALICIOUS`) vs DS-004 (`BENIGN_VALIDATION`), ensuring feature existence acts strictly behaviorally rather than serving as an explicit dataset proxy label.

## 11. Schema
Output Schema (Truncated for brevity):
- `model_safe_index` (int, Linker)
- `label` (string, Target)
- `flow_duration`, `total_packets`, `bytes_per_second` (float/int, FLOW statistics)
- `packet_length_mean`, `fwd_packet_length_mean` (float, PACKET statistics)
- `iat_mean`, `rev_iat_std` (float, IAT statistics)
- `sni_present`, `ja3_hash`, `ja4` (boolean/string, TLS / FINGERPRINT metadata)

## 12. Validation Results
- Constraints checking explicitly confirmed NO absolute timestamps, NO IP allocations, NO ports, and NO domain tracking variables bypassed the filter.
- Identical initial data frames correctly rendered identical hash-validated output mechanisms securely.

## 13. Known Limitations
"MODEL-SAFE does not mean leakage-free under all experimental splits."
The dataset-source confounding between DS-004 (benign validation originating from specific configurations) and DS-008 (noisy malware captures) remains a known scientific limitation. The model-safe implementation purges programmatic leakage but cannot organically fix systemic environmental behavioral differences inherent to heterogeneous network collections.

## 14. Open Scientific Decisions
- Feature Imputation Strategy for downstream classifiers (`PENDING_PILOT_VALIDATION`).
- Whether sequence embeddings vs statistical abstractions provide superior generalization (`PENDING_PILOT_VALIDATION`).
- The impact of duplicate beaconing structures on cross-validation leakages if naive random splitting is deployed later (`PENDING_PILOT_VALIDATION`).
