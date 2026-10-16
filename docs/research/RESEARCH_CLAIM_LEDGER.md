# ETTH Research Claim Ledger

**Project:** Encrypted Traffic Threat Hunter (ETTH)  
**Date:** October 16, 2026  
**Auditor:** Antigravity Research Integrity Agent  
**Repository Branch:** `research/phase-12-paper-manuscript`  

---

## 1. Classification Taxonomy

Every scientific claim in the ETTH project is evaluated and categorized under strict academic evidentiary criteria:
1. **VERIFIED**: Substantiated by reproducible artifacts, unconfounded datasets, and rigorous statistical tests.
2. **PROVISIONALLY SUPPORTED**: Mechanically validated by engineering pipelines, but scientifically constrained by sample size or source confounding.
3. **NOT YET TESTED**: Conceptually designed (e.g., Phase 9 unconfounded benchmarks or Phase 10 deep sequence models), but no empirical runs completed.
4. **UNSUPPORTED / CONTRADICTED**: Refuted by empirical evidence or invalidated by methodological flaws.
5. **BLOCKED BY MISSING DATA**: Cannot be evaluated until an unconfounded, representative benign dataset is admitted.

---

## 2. Research Claims Ledger

### Claim 1: Zero-Decryption Metadata Sufficiency
> **Claim:** "Network-observable TLS handshake metadata and bidirectional flow behavioral features can be extracted and modeled without decrypting packet payloads, terminating TLS sessions, or retaining packet plaintext."
- **Status:** **VERIFIED**
- **Supporting Evidence:**
  - `pipeline/flow_reconstruction.py`: Bidirectional 5-tuple flow aggregation parses packet headers only.
  - `pipeline/tls_fingerprinting.py`: Extracts JA3/JA3S/JA4 hashes and cipher suites strictly from unencrypted Record Layer `ClientHello` and `ServerHello` headers.
  - `pipeline/model_safe_generator.py`: Verifies zero payload retention and strips all network addresses/ports to prevent memorization.
- **Source Artifacts:**
  - Unit tests `test_flow_reconstruction.py`, `test_tls_fingerprinting.py`, and `test_model_safe.py` (46/46 passing).
  - Phase 6 Final Validation Audit (`data/manifests/phase6_final_audit.json`).
- **Limitations:** Cannot detect threats inside TLS connections where the initial handshake was missed (mid-stream capture) or where TLS handshake records are fully encrypted (e.g., complete ECH / Encrypted ClientHello without cleartext Outer ClientHello).

---

### Claim 2: Engineering Robustness of Multi-Track Detection Pipeline
> **Claim:** "The ETTH preprocessing and inference engine can deterministically partition network flows into five mutually exclusive experimental tracks (A: Flow-only, B: JA3-only, C: JA4-only, D: JA3+Flow, E: JA4+Flow) under group-aware cross-validation without cross-fold data leakage."
- **Status:** **VERIFIED**
- **Supporting Evidence:**
  - `step7_step5_pilot_run.py`: Executed 5-fold `GroupShuffleSplit` grouping on `behavioral_hash` (SHA-256 of behavioral vector) with random seed 42.
  - Verified `intersection(train_groups, test_groups) == empty` across all 5 splits.
  - Imbalanced preprocessing pipelines (`imblearn`) strictly fitted on training partitions only.
- **Source Artifacts:**
  - `data/experiments/phase7_step5_pilot/pilot_summary.json`
  - `data/experiments/phase7_step5_pilot/pilot_fold_results.csv`
  - `tests/test_experiments.py` (passes feature-family mutual exclusion tests).
- **Limitations:** Validates mechanical software execution only; does not validate real-world detection generalizability.

---

### Claim 3: Near-Perfect Pilot Detection Accuracy (PR-AUC 1.0, F1 ~0.99)
> **Claim:** "ETTH machine learning models achieve 99.8%–100% PR-AUC and F1 scores in detecting encrypted malicious traffic."
- **Status:** **PROVISIONALLY SUPPORTED AS AN ENGINEERING DEMONSTRATION; SCIENTIFICALLY CONTRADICTED AS GENERALIZED PERFORMANCE**
- **Supporting Evidence:**
  - Models (LogisticRegression, RandomForest, XGBoost) trained in Phase 7 Step 5 produced:
    - Track A (Flow-only, 80 features): Avg PR-AUC 1.000, Avg F1 0.999
    - Track B (JA3-only, 1 feature): Avg PR-AUC 0.997, Avg F1 0.982
    - Track C (JA4-only, 1 feature): Avg PR-AUC 0.998, Avg F1 0.982
    - Track D (JA3+Flow, 81 features): Avg PR-AUC 1.000, Avg F1 0.995
    - Track E (JA4+Flow, 81 features): Avg PR-AUC 1.000, Avg F1 0.995
- **Known Limitations & Methodological Confounding:**
  - **Severe Class Imbalance**: 2,543 Malicious flows (from Malware-Traffic-Analysis.net) vs. only 6 Benign validation flows (from CipherSpectrum) — an imbalance ratio of **424:1**.
  - **Capture Environment Confounding**: DS-008 traffic was captured in chaotic, noisy virtual malware execution sandboxes; DS-004 traffic was captured in clean, isolated, single-flow benign web server environments.
  - **Spurious Environmental Artifacts**: Models learned to distinguish the capture infrastructure (sandbox background noise vs. clean server) rather than intrinsic threat signatures.
- **Conclusion:** These metrics **MUST NOT** be presented in academic publications as generalized detection efficacy.

---

### Claim 4: JA4 Provides Superior Discriminative Power Compared to JA3
> **Claim:** "Modern JA4 fingerprints provide measurably superior malware detection and lower collision rates than legacy JA3 MD5 hashes."
- **Status:** **NOT YET TESTED (UNSUPPORTED ON CURRENT DATASET)**
- **Supporting Evidence:**
  - In Phase 7 Step 5 pilot evaluation, Track B (JA3-only) achieved PR-AUC 0.997 and F1 0.982; Track C (JA4-only) achieved PR-AUC 0.998 and F1 0.982.
  - The performance difference (+0.001 PR-AUC) is statistically indistinguishable ($p > 0.05$) due to the extremely small benign validation sample ($N=6$).
- **Blocker:** Requires an unconfounded benign corpus with diverse, modern browser and enterprise application handshakes to test collision resistance and discriminative efficacy.

---

### Claim 5: Deep Learning Sequence Models Outperform Tabular Summary Statistics
> **Claim:** "Deep sequence models (1D-CNN, BiLSTM, Transformer) trained on raw packet length and inter-arrival time sequences achieve higher threat detection fidelity than aggregate tabular flow features."
- **Status:** **NOT YET TESTED**
- **Supporting Evidence:** Raw sequence arrays (`packet_lengths_sequence`, `inter_arrival_times_sequence`) are preserved in `pipeline/flow_reconstruction.py` schemas, but Phase 10 deep learning sequence modeling has not yet been executed.
- **Blocker:** Dependent on Phase 8 unconfounded dataset acquisition and Phase 10 implementation.

---

### Claim 6: Cross-Sensor Identity Resolution Across Zeek, Suricata, and eBPF
> **Claim:** "ETTH reliably correlates network flows across heterogeneous sensors (Zeek, Suricata, and eBPF) using IP 5-tuples and timestamps."
- **Status:** **PROVISIONALLY SUPPORTED WITH OPERATIONAL LIMITATIONS**
- **Supporting Evidence:**
  - `backend/event_sources/zeek_source.py` and `suricata_source.py` normalize distinct sensor schemas to the identical `FlowDetails` and `TLSDetails` contracts.
  - Integration tests in `tests/test_sensors_pipeline_integration.py` confirm identical downstream model routing and target attribution.
- **Limitations:** Cross-sensor identity resolution can fail in the presence of Network Address Translation (NAT), multi-tenant cloud CDN Anycast routing, or clock skew across sensor hosts. IP-only correlation is explicitly avoided by the `TargetResolver` engine.

---

## 3. Summary of Evidence Status

| Claim Description | Scientific Verdict | Action Required for Conference Readiness |
| :--- | :---: | :--- |
| Zero-Decryption Feature Extraction | **VERIFIED** | Formally document privacy boundary and ECH edge cases in manuscript. |
| Leakage-Safe Multi-Track Pipeline | **VERIFIED** | Include reproducibility code and `GroupShuffleSplit` verification in Section 4. |
| Pilot Detection Performance (~100% PR-AUC) | **CONFOUNDED** | Frame strictly as an engineering smoke test; report confounding prominently. |
| JA4 vs. JA3 Comparative Superiority | **NOT YET TESTED** | Await unconfounded benign dataset (Phase 8/9). Mark as provisional. |
| Deep Learning Sequence Superiority | **NOT YET TESTED** | Defer claims to future work or leave Phase 10 results explicitly pending. |
| Multi-Sensor Normalization | **PROVISIONALLY SUPPORTED** | Document NAT and clock-skew operational caveats in Section 3. |
