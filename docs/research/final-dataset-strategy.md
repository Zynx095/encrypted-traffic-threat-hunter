# ETTH Final Dataset Strategy

## 1. Purpose
This document defines the final dataset strategy for the Encrypted Traffic Threat Hunter (ETTH) research project. The strategy is derived strictly from empirical evidence regarding dataset capabilities, limitations, and alignment with the project's core research question. 

## 2. Research Requirements
The core research question asks:
*"Does combining TLS fingerprint features (JA4/JA3S) with encrypted-flow behavioral features provide statistically significant improvement in detection performance compared to using either feature family in isolation?"*

To test this, the project requires:
- Raw PCAP availability (mandatory for JA4 extraction)
- TLS 1.3 representation (highly important for modern relevance)
- Both ClientHello and ServerHello availability
- JA4 and JA3 computability
- Flow feature and packet-level sequence availability
- Both Malicious and Benign labels

## 3. Empirical Evidence Summary
Empirical Phase 5 verification has shown:
- **DS-001 (ISCXVPN2016):** Contains raw PCAPs but lacks malware traffic. Dominant TLS 1.2 and unencrypted traffic.
- **DS-002 (CIC-Darknet2020):** Lacks raw PCAPs entirely.
- **DS-003 (USTC-TFC2016):** Contains benign and malware traffic. However, sampled malware traffic utilized obsolete SSL 3.0 (no extensions), and benign traffic lacked ClientHellos. JA4 is mathematically not computable.
- **DS-004 (CipherSpectrum):** Perfect TLS 1.3 representation, flawless JA4 computability, and bidirectional flow extraction. However, it is an application classification dataset representing 40 web domains and completely lacks malware traffic.
- **DS-005 (CSTNET-TLS1.3):** Distributed only as TSV files, making JA4 extraction impossible.

## 4. Dataset Capability Matrix
| Dataset | Raw PCAP | TLS 1.3 | JA4 Computable | Flow Features | Malware Traffic | Benign Traffic |
|---------|----------|---------|----------------|---------------|-----------------|----------------|
| DS-001 | YES | NO | PENDING | YES | **NO** | YES |
| DS-002 | **NO** | NO | **NO** | YES | NO | YES |
| DS-003 | YES | NO | **NO** | YES | YES | YES |
| DS-004 | YES | YES | YES | YES | **NO** | YES |
| DS-005 | **NO** | YES | **NO** | NO | NO | YES |

## 5. Experiment Compatibility Matrix
| Dataset | A (Flow-only) | B (JA3-only) | C (JA4-only) | D (JA3+Flow) | E (JA4+Flow) | Role |
|---------|---------------|--------------|--------------|--------------|--------------|------|
| DS-001 | SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | LEGACY_BENIGN |
| DS-002 | SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | REJECTED |
| DS-003 | SUPPORTED | PENDING | **NOT_SUPPORTED** | NOT_SUPPORTED | NOT_SUPPORTED | LEGACY_MALWARE |
| DS-004 | SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | MODERN_TLS_VALIDATION |
| DS-005 | NOT_SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | NOT_SUPPORTED | REJECTED |

## 6. Dataset Roles
Because no single dataset fulfills all requirements, ETTH must adopt a multi-dataset strategy (Strategy D) where specific datasets support specific, isolated validation tasks.

- **Primary Dataset:** PENDING (Malware Dataset Required)
- **Secondary Dataset:** DS-003 (USTC-TFC2016)
- **Validation Dataset:** DS-004 (CipherSpectrum)

## 7. Primary Dataset Decision
**Decision: PENDING**
Current registered datasets do not yet provide a fully verified primary malware dataset for JA4 + Flow experiments. No current candidate has both malware labels and JA4 computability. A new dataset must be acquired.

## 8. Secondary Dataset Decision
**Decision: DS-003 (USTC-TFC2016)**
Assigned the role `LEGACY_FLOW_VALIDATION`. It will be used exclusively to test the Flow-only configuration (Experiment A) because it is the only current dataset with verifiable malware flow features. It cannot support the core JA4 configurations.

## 9. Validation Dataset Decision
**Decision: DS-004 (CipherSpectrum)**
Assigned the role `MODERN_TLS_VALIDATION`. It will be used as the rigorous benign baseline for modern TLS 1.3 traffic, validating JA4 parsing tools, verifying flow feature robustness under TLS 1.3, and providing a test bed for application-layer benign profiles.

## 10. Rejected Datasets
- **DS-001 (ISCXVPN2016):** Rejected for threat hunting. It lacks malware labels and utilizes deprecated encryption.
- **DS-002 (CIC-Darknet2020):** Rejected due to lack of raw PCAPs.
- **DS-005 (CSTNET-TLS1.3):** Rejected due to lack of raw PCAPs.

## 11. Pending Dataset Verification
**DATASET_REQUIRED: Modern Malware PCAPs**
A new dataset containing modern, TLS 1.2+ encrypted malware or C2 traffic must be sourced and verified for JA4 computability. (e.g., Stratosphere IPS captures, CIC-MalMem2022).

## 12. Multi-Dataset Leakage Risks
Combining a malware dataset (when acquired) with CipherSpectrum (benign) creates severe dataset-source leakage risk. The classifier is extremely likely to learn the IP subnet of the malware sandbox versus the IP subnet of the UNSW capture environment, rather than learning traffic behavior. 
- *Risk:* The model achieves 99% accuracy by learning "Dataset A = benign, Dataset B = malware".

## 13. Normalization Requirements
To mitigate dataset-source leakage across the multi-dataset strategy:
- All IPs (Source and Destination) must be masked or removed.
- All Ports (Source and Destination) must be excluded from feature vectors.
- SNI extensions must be masked or tokenized carefully to prevent domain memorization.
- MAC addresses must be excluded.

## 14. Class-Balance Strategy
The extreme imbalance of typical captures must be countered using stratified splitting. Once the final primary malware dataset is acquired, random undersampling of the benign dataset (CipherSpectrum) will be used to enforce a maximum 10:1 benign-to-malware ratio during training.

## 15. Temporal-Split Strategy
Not applicable to the currently disjoint multi-dataset strategy until the primary malware dataset provides temporal metadata. If possible, test sets should be sampled from temporally later captures than the training set to prove temporal generalization.

## 16. Cross-Dataset Generalization Strategy
The ultimate proof of the JA4+Flow detection method will require training a model on the combined dataset (Primary Malware + subset of DS-004 Benign) and testing it against a completely distinct, unseen malware capture environment to prove it learned behavioral features, not capture artifacts.

## 17. Impact on Experiments A–E
- **Experiment A (Flow-only):** Unimpacted. Can be conducted on DS-003 and DS-004 immediately.
- **Experiment B (JA3-only):** Blocked pending Primary Malware Dataset.
- **Experiment C (JA4-only):** Blocked pending Primary Malware Dataset.
- **Experiment D (JA3+Flow):** Blocked pending Primary Malware Dataset.
- **Experiment E (JA4+Flow):** Blocked pending Primary Malware Dataset.

## 18. Impact on H0/H1
The null hypothesis (H0: JA4+Flow offers no significant improvement) cannot be scientifically rejected or accepted until the primary malware dataset is sourced. Attempting to test H1 on currently registered datasets would be scientifically invalid due to the total absence of JA4 computable malware records.

## 19. Remaining Scientific Risks
Even after a JA4-capable malware dataset is found, the risk of dataset-source leakage remains the most dangerous scientific threat to this project. The features utilized by JA4 and Flow metrics must be heavily audited post-training via SHAP values to confirm the model hasn't found a shortcut.

## 20. Final Recommendation
**Primary dataset selection remains pending acquisition and empirical verification of a malware-capable JA4 dataset.**
Implementation of Phase 6 (Data Pipeline Construction) MUST be blocked until the `DATASET_REQUIRED: Modern Malware PCAPs` verification task is successfully completed.
