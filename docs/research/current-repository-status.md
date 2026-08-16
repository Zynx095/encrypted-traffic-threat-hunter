# Current Repository Status

**Date:** 2026-08-16
**Purpose:** Authoritative snapshot of the repository state after completion of Phase 6 and Stage 6.5.

## 1. Research Status
- **Research:** ACTIVE
- **Phase 5 — Dataset Strategy:** CLOSED
- **Phase 6 — Data Ingestion & Preprocessing:** CLOSED
- **Stage 6.5 — Expanded Corpus Rebuild:** COMPLETE
- **Phase 7 — ML / Experimental Evaluation:** NOT STARTED
- **Engineering Pipeline:** READY
- **Scientific Evaluation:** READY WITH CONDITIONS
- **ML Models:** NOT YET IMPLEMENTED
- **Final Research Results:** NOT YET AVAILABLE
- **Real-Time Detection:** NOT YET IMPLEMENTED

## 2. Current Dataset Strategy
### Primary: DS-008 — Malware-Traffic-Analysis.net
- **Role:** Modern TLS malware and C2 baseline
- **Evidence:** Empirically verified via phase-5-candidate-verification-report.md
- **Metrics:**
  - PCAPs verified: 10 approved MTA PCAP samples
  - Total reconstructed flows: 2,543
  - TLS flows with ClientHello: 200
  - JA3 / JA3S / JA4 extracted: 200 each

### Validation: DS-004 — CipherSpectrum
- **Role:** Modern TLS benign validation baseline
- **Evidence:** Empirically verified via phase-5-empirical-verification-report.md
- **Metrics:**
  - PCAPs verified: 6
  - Total reconstructed flows: 6
  - TLS flows with ClientHello: 6
  - JA3 / JA3S / JA4 extracted: 6 each

### Pending: Potential Unified Datasets
- **DS-006 — Beyond JA4+:** Academic access pending (requires academic request for full PCAPs)
- **DS-007 — Annotated Encrypted Network Traffic:** Academic access pending (raw PCAPs require justified request)

## 3. Current Data Statistics (Post Stage 6.5)
- **Total flows:** 2,549 (2,543 malicious + 6 benign validation)
- **TLS flows:** 200
- **JA3-capable flows:** 200
- **JA3S-capable flows:** 202
- **JA4-capable flows:** 200
- **Behavioral feature rows:** 2,549
- **Model-safe rows:** 2,549

## 4. Current Experimental Datasets (Post Stage 6.5)
- **Experiment A (Flow-only):** 2,068 rows
- **Experiment B (JA3-only):** 160 rows
- **Experiment C (JA4-only):** 160 rows
- **Experiment D (JA3 + Flow):** 160 rows
- **Experiment E (JA4 + Flow):** 160 rows

## 5. Duplicate Analysis (Post Stage 6.5)
- **Duplicate groups:** 75
- **Exact duplicate behavioral rows:** 1,005
- **Cross-PCAP duplicates:** 0
- **Cross-label duplicates:** 0
- **Model-safe leakage violations:** 0

## 6. Current Leakage Controls
The model-safe representation excludes all deterministic identifiers:
- IP addresses (src/dst) - Host memorization
- Ports (src/dst) - Service memorization
- MAC addresses - Hardware identification
- Raw SNI / domain strings - Environment fingerprinting
- Absolute timestamps - Temporal leakage
- Dataset identifiers - Dataset-source leakage
- Source filenames - Capture-session memorization
- Flow identifiers - Provenance leakage

Retained information consists of legitimate behavioral and TLS structural features:
- Flow duration, packet counts, byte statistics
- Packet-length distributions (mean, std, percentiles)
- Inter-arrival time distributions (global, directional)
- Directional asymmetry ratios
- Burst and idle-gap statistics
- TLS structural metadata (version, handshake presence)
- SNI presence (boolean only — not the domain string)
- JA3, JA3S, JA4 fingerprint hashes
- Raw packet/timing sequences (for potential deep-learning use)

Provenance metadata is preserved in a separate audit table linked by a `model_safe_index`, ensuring reproducibility without exposing identifiers to ML models.

## 7. Current Test Status
- **Total tests:** 46
- **Passed:** 46
- **Failed:** 0
- **Skipped:** 0
- Tests cover: PCAP ingestion, flow reconstruction, TLS fingerprint extraction, behavioral feature derivation, model-safe leakage constraints, and experimental dataset isolation (A–E feature-family mutual exclusion)

## 8. Scientific Limitations
### Dataset-Source / Capture-Environment Confounding
The current experimental datasets combine traffic from two substantially different capture environments:
- **DS-004 (Benign):** Clean, isolated TLS validation
- **DS-008 (Malicious):** Chaotic malware sandbox

**Consequence:** A model may learn to distinguish capture environments rather than genuine malicious behavior. For example, identifying "broken" or "noisy" flows as malicious because DS-008 inherently contains more non-TLS background traffic — not because the model has learned to detect C2 communication patterns.

This is a known and documented limitation. Aggressive leakage controls are implemented, but environmental confounding cannot be fully resolved without a unified dataset containing both benign and malicious traffic from the same capture infrastructure.

### Benign Sample Size
The current verified benign validation sample consists of only **6 flows** from DS-004. While this is sufficient for pipeline validation and pilot experimentation, it is insufficient for robust statistical conclusions about detection performance.

### Class Imbalance
**Extreme class imbalance:** 2,543 MALICIOUS vs 6 BENIGN_VALIDATION (~424:1 ratio)

## 9. Phase 7 Readiness
**Status:** READY WITH CONDITIONS

**Primary Blocker:** Severe class imbalance (2,543:6 ratio) requiring appropriate ML techniques during Phase 7 experimentation.

**Known Blockers for Phase 7:**
1. Severe class imbalance (2,543:6 ratio)
2. Dataset-source confounding
3. Only 6 benign validation flows
4. Fingerprint experiments have substantially smaller usable populations than Flow-only (160 vs 2,068 rows)
5. NaN/missing-value policy requires explicit Phase 7 handling
6. SMOTE or other resampling MUST occur inside training folds only
7. Feature scaling MUST be fitted only on training folds
8. Group-aware splitting must be preserved
9. Duplicate behavioral structures must not cross train/test boundaries

## 10. Pending Academic Datasets
- **DS-006 — Beyond JA4+:** Requires academic request for full PCAPs
- **DS-007 — Annotated Encrypted Network Traffic:** Requires justified request for raw PCAPs

## 11. Future Work
Phase 7 should focus strictly on **Empirical Dataset Verification and Pipeline Initialization**. This means downloading sample PCAPs, executing the verification queue to test JA4 extraction and flow filtering, finalizing the dataset selection based on empirical results, and setting up the foundational data ingestion pipeline.

No ML model has been trained. No accuracy, F1, ROC-AUC, or other performance metric currently exists for this project.