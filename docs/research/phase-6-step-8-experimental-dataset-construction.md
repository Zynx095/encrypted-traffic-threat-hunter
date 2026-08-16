# Phase 6 Step 8 — Experimental Dataset Construction

## 1. Purpose
This step constructs five independent dataset configurations (Experiments A through E) to isolate the discriminative contribution of the TLS fingerprint family relative to flow-level behavioral features. The construction explicitly filters out missing fingerprints, prevents cross-contamination of isolated feature sets, and enforces a leakage-free, group-aware train/test split.

## 2. Input Dataset
The input is the leakage-controlled `data/processed/model_safe/flows_model_safe.parquet` containing 1,460 abstract behavioral flow representations, alongside its associated provenance mapping `flows_provenance.parquet`.

## 3. Fingerprint Coverage and Missing-Value Policy
- **Total Input Rows:** 1460
- **JA3 / JA3S / JA4 Coverage:** 68 rows
- **Policy:** Experiments isolating fingerprints (B, C, D, E) enforce a strict inclusion policy, filtering the dataset to ONLY the 68 rows containing a valid parsed ClientHello. Semantic missingness (`NaN`) is explicitly rejected from these models to test fingerprint validity on available data. Experiment A (Flow Only) retains all 1460 rows, as flow statistics are universally available.

## 4. Duplicate Analysis & Grouping Strategy
Analysis identified 553 duplicated exact behavioral geometries (e.g., automated malware beacon loops). To prevent these identical vectors from appearing simultaneously in the Train and Test subsets, the splitting algorithm maps each exact behavioral representation to a deterministic `behavioral_hash`.
- **Grouping Strategy:** `GroupShuffleSplit` operating on `behavioral_hash`.
- **Result:** Exact duplicates are guaranteed to remain atomically bound to a single split. No exact duplicate crosses the test boundary.

## 5. Split Strategy & Class Balance
- **Methodology:** 80/20 train/test split via `GroupShuffleSplit`.
- **Deterministic Seed:** 42

**Experiment A (Flow Only):**
- Train: 807 rows (802 MALICIOUS, 5 BENIGN_VALIDATION)
- Test: 653 rows (652 MALICIOUS, 1 BENIGN_VALIDATION)

**Experiments B/C/D/E (Fingerprint Subsets):**
- Train: 54 rows (49 MALICIOUS, 5 BENIGN_VALIDATION)
- Test: 14 rows (13 MALICIOUS, 1 BENIGN_VALIDATION)

## 6. Experiment Definitions & Feature Counts

### Experiment A (Flow Only)
- **Features:** 83 variables (Duration, Packet Counts, Length Stats, IAT Stats, Burst Stats, TLS Structural flags) + preserved raw sequences.
- **Constraints:** NO JA3, NO JA4, NO JA3S.

### Experiment B (JA3 Only)
- **Features:** 1 variable (`ja3_hash`)
- **Constraints:** NO JA4, NO JA3S, NO Flow stats.

### Experiment C (JA4 Only)
- **Features:** 1 variable (`ja4`)
- **Constraints:** NO JA3, NO JA3S, NO Flow stats.

### Experiment D (JA3 + Flow)
- **Features:** 84 variables (`ja3_hash` + Flow families)
- **Constraints:** NO JA4, NO JA3S.

### Experiment E (JA4 + Flow)
- **Features:** 84 variables (`ja4` + Flow families)
- **Constraints:** NO JA3, NO JA3S.

## 7. Dataset-Source Balance & Leakage Checks
- Dataset identifiers (`dataset_id`, `source_file`) and specific deterministic metadata (`model_safe_index`, `flow_id`) were intentionally blocked from entering the ML schema.
- A rigorous test suite validates the mutual exclusion properties bounding each experiment (e.g., verifying Experiment E strictly lacks `ja3_hash` while retaining `ja4`).
- Scaling and encoding transformers are intentionally deferred to Phase 7 to prevent fitting over test statistics.

## 8. Known Limitations & Scientific Warnings
**SUPPORTED WITH CONDITIONS.**
The current experimental datasets are constrained by a critical scientific bottleneck: dataset-source confounding. The MALICIOUS class originates purely from DS-008 environments, while the BENIGN_VALIDATION class originates purely from DS-004. Any detected generalization may be acting as an environmental proxy identifier. The results of models utilizing these datasets should be treated as procedural verifications of the pipeline architecture rather than definitive validations of the research hypothesis.

## 9. Phase 7 Requirements
- One-Hot Encode categorical strings (`ja3_hash`, `ja4`, `alpn_value`) natively within the cross-validation framework to prevent train-test contamination.
- Implement explicit handling for severe class imbalance without leaking synthetic geometries (e.g. SMOTE inside the cv-loop).
- Address sequence integration architectures for Deep Learning endpoints.
