# ETTH Final Dataset Decision

## 1. Executive Decision
**MULTI-DATASET STRATEGY SELECTED**
(With Phase 6 authorized under strict leakage conditions)

## 2. Evidence Summary
Through empirical verification and rigorous research, ETTH has established the following ground truth regarding available datasets:
- No single publicly downloadable dataset currently provides raw PCAPs containing both modern TLS 1.3 malware and comparable benign traffic with extractable JA4 fingerprints.
- **DS-008 (MTA)** provides exceptional, empirically verified modern TLS 1.3 malware/C2 captures from which JA4 and bidirectional flow features can be extracted. However, it lacks a benign baseline.
- **DS-004 (CipherSpectrum)** provides an excellent, empirically verified modern TLS 1.3 benign baseline with fully extractable JA4 and flow features. However, it lacks malware.
- **DS-006 / DS-007 (BUT Datasets)** represent the theoretical ideal (unified malware and benign modern TLS captures), but raw PCAP access is strictly gated behind academic approval, which remains pending.

## 3. Candidate Comparison
- **Unified Candidates (DS-006, DS-007):** Scientifically superior due to shared capture environments, but blocked by accessibility.
- **DS-008 (Malware):** High empirical suitability. Accessible, verified TLS 1.3, verified JA4.
- **DS-004 (Benign):** High empirical suitability. Accessible, verified TLS 1.3, verified JA4.
- **Legacy Candidates (DS-001, DS-003):** Obsolete TLS or flawed flow architectures. Rejected for the primary JA4 experiments.

## 4. Strategy Comparison
### STRATEGY A — UNIFIED DATASET
- **Status:** BLOCKED (Pending Academic Access).
- **Verdict:** Highly recommended if access is granted.
### STRATEGY B — DS-008 + BENIGN DATASET (e.g., DS-004)
- **Status:** SCIENTIFICALLY RISKY.
- **Verdict:** High risk of dataset-source leakage. The model is highly likely to learn the differences between the MTA capture sandbox and the CipherSpectrum enterprise network rather than true malware behavior.
### STRATEGY C — DS-008 PRIMARY + DS-004 VALIDATION
- **Status:** SUPPORTED WITH CONDITIONS.
- **Verdict:** We will construct a synthetic combined dataset for pipeline engineering and preliminary binary classification, acknowledging it as a cross-dataset baseline. We will strictly apply normalization.

## 5. Leakage Analysis (For DS-008 + DS-004 Combination)
Combining DS-008 (Malware) and DS-004 (Benign) introduces severe environmental confounders:
- **IP/Port Leakage:** NOT_MITIGABLE if left raw. MITIGABLE by aggressively stripping all IPs and Ports from the final feature vector.
- **MAC Leakage:** MITIGABLE (Strip L2 data).
- **SNI/DNS Leakage:** PARTIALLY_MITIGABLE. Malware domains differ fundamentally from benign domains, but the JA4 'd' (domain) identifier might correlate strongly with the dataset.
- **Timestamp/Temporal Leakage:** MITIGABLE. Strip absolute timestamps; use only relative inter-arrival times (IAT).
- **Capture-environment Leakage:** PARTIALLY_MITIGABLE. Network latency (RTT), MTU sizes, and packet fragmentation may perfectly separate the two datasets.
- **OS/Browser Leakage:** UNKNOWN. If DS-004 uses Chrome/Mac and DS-008 uses Windows/IE, JA3/JA4 will perfectly separate the datasets based on OS, not malware.

## 6. Recommended Dataset Strategy
**Adopt Strategy C (Multi-Dataset Synthesis) while aggressively pursuing Strategy A.**
We will proceed with DS-008 and DS-004 to engineer the Phase 6 data pipeline (PCAP → Features). This ensures technical progress is unblocked. Simultaneously, we maintain P0 requests for DS-006/007 to ensure the final ML evaluation (Phase 7/8) is scientifically defensible.

## 7. Primary Dataset (Malware Base)
**DS-008 (Malware-Traffic-Analysis.net)**
- **Reason:** Only verified source of raw PCAPs containing modern TLS 1.3 C2 traffic.
- **Known Limitations:** Sandbox artifacts, no benign traffic.
- **Required Mitigations:** Drop IP, Port, MAC, and absolute timestamps.

## 8. Secondary / Validation Datasets (Benign Base)
**DS-004 (CipherSpectrum)**
- **Role:** Modern TLS benign baseline and pipeline validation.
- **Known Limitations:** Enterprise traffic properties may clash with MTA sandbox properties.
- **Required Mitigations:** Flow feature normalization (scaling IAT and lengths).

## 9. Experimental Compatibility
- **A (Flow-only):** SUPPORTED WITH CONDITIONS (Leakage risk high).
- **B (JA3-only):** SUPPORTED WITH CONDITIONS (OS/Browser leakage risk).
- **C (JA4-only):** SUPPORTED WITH CONDITIONS.
- **D (JA3 + Flow):** SUPPORTED WITH CONDITIONS.
- **E (JA4 + Flow):** SUPPORTED WITH CONDITIONS.

## 10. Known Limitations
The binary classifier trained on the DS-008/DS-004 split will likely overfit to the capture environment. Accuracy metrics from this experiment must be reported with an asterisk (*) indicating dataset-source confounding.

## 11. Required Mitigations
1. **Strict Feature Selection:** The ML pipeline must absolutely exclude IP addresses, Ports, MAC addresses, and absolute timestamps.
2. **Robustness Testing:** Model must be tested on a hold-out sample from a completely different environment (e.g., DS-009 or live capture) to measure actual generalization.
3. **JA4 Component Isolation:** We may need to evaluate the `a`, `b`, and `c` components of JA4 separately to ensure the model isn't just memorizing ALPN or SNI length differences.

## 12. Academic Access Requirements
**DS-006 and DS-007 Access:** RECOMMENDED.
- **Reasoning:** It is highly worth waiting for (or concurrently processing) these datasets. If access is granted, they immediately replace the DS-008+DS-004 combination as the primary unified experiment.

## 13. Phase 6 Readiness
**READY WITH CONDITIONS.**
Phase 6 (Data Ingestion and Preprocessing Pipeline) is authorized to begin. Building the PySpark/Python data pipeline to parse PCAPs, extract JA4, compute flow statistics, and output feature matrices is dataset-agnostic. We will use DS-008 and DS-004 to build and test this pipeline. 

## 14. Final Decision
MULTI-DATASET STRATEGY SELECTED.
Proceed to Phase 6 using DS-008 (Malware) and DS-004 (Benign) to engineer the pipeline, while keeping the door open for DS-006/DS-007 substitution upon academic approval.

## 15. Remaining Research Risks
The core ETTH hypothesis (JA4 + Flow > JA4 alone) might artificially succeed if Flow features perfectly memorize the DS-004 vs DS-008 network latency differences. Careful baseline normalization is mandatory in Phase 7.
