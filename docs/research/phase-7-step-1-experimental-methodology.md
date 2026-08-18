# Phase 7 Step 1 — Experimental Methodology

## 7.1 Research Hypothesis

**Research Hypothesis:** Whether combining TLS fingerprint features with encrypted-flow behavioral features improves malicious encrypted-traffic detection compared with either feature family alone.

This research distinguishes the performance between five precise feature family configurations:
* **Flow-only**: Encrypted-flow behavioral features exclusively.
* **JA3-only**: JA3 fingerprint features exclusively.
* **JA4-only**: JA4 fingerprint features exclusively.
* **JA3 + Flow**: Combined JA3 and flow behavioral features.
* **JA4 + Flow**: Combined JA4 and flow behavioral features.

This hypothesis is currently being investigated and has **not** been proven.

## 7.2 Experimental Configurations

| Configuration | Active Feature Families | Forbidden Feature Families | Intended Research Question | Current Usable Population (Rows) |
| :--- | :--- | :--- | :--- | :--- |
| **A — FLOW ONLY** | Encrypted-flow behavioral features | JA3, JA4 | Baseline detection capability using only behavioral statistics. | 2,118 |
| **B — JA3 ONLY** | JA3 fingerprint | Flow behavioral features, JA4 | Baseline detection capability using only JA3. | 160 |
| **C — JA4 ONLY** | JA4 fingerprint | Flow behavioral features, JA3 | Baseline detection capability using only JA4. | 160 |
| **D — JA3 + FLOW** | JA3 fingerprint, Flow behavioral features | JA4 | Does JA3 + Flow improve over the isolated baselines? | 160 |
| **E — JA4 + FLOW** | JA4 fingerprint, Flow behavioral features | JA3 | Does JA4 + Flow improve over the isolated baselines? | 160 |

## 7.3 Dataset Boundary

The current expanded corpus (v2) consists of:
* **MALICIOUS (DS-008)**: 2,543 rows
* **BENIGN_VALIDATION (DS-004)**: 6 rows
* **Total Model-Safe Rows**: 2,549 rows

> [!WARNING]
> **Important Limitation:** `BENIGN_VALIDATION` is a limited validation baseline comprising only 6 flows. It must **not** be described or interpreted as a representative large-scale benign Internet population.

## 7.4 Dataset-Source Confounding

**Known Limitation:**
* All **DS-008** samples represent malware traffic strictly sourced from `Malware-Traffic-Analysis.net`.
* All **DS-004** samples represent the benign validation baseline from `CipherSpectrum`.

Because these two sources differ fundamentally in capture environment, topology, and traffic characteristics (e.g., sandbox artifacts), there is a severe risk that models will learn dataset-source environmental characteristics instead of actual malicious behavior. This limitation must remain permanently attached to the interpretation of all Phase 7 results. The confounding has **not** been solved.

## 7.5 Grouping and Split Rules

The duplicate grouping mechanism is officially frozen as: **`behavioral_hash`**.

* **Split Strategy:** `GroupShuffleSplit`
* **Random Seed:** `random_state = 42`
* **Rule:** Identical behavioral structures (sharing the same `behavioral_hash`) must remain strictly within a single partition (either training or validation/test). They must never cross boundaries.
* **Justification:** Sandbox executions frequently produce exact duplicate behavioral telemetry due to repeated polling or beaconing mechanisms. Allowing these duplicates to bleed across train/test splits would result in catastrophic data leakage and artificially inflated evaluation metrics.
* **Limitations:** The small number of source PCAPs (10 for DS-008) means that strict grouping drastically reduces the available variance and fold-count in cross-validation, potentially leading to unstable estimates.

## 7.6 Leakage Prevention

**Prohibited Features:**
The following features are strictly forbidden from the model-safe dataset to prevent trivial leakage:
* IP addresses
* Ports
* MAC addresses
* Absolute timestamps
* Source filenames
* Dataset identifiers
* Provenance identifiers
* Behavioral duplicate groups (as predictive features)

**Preprocessing Leakage Prevention:**
It is strictly forbidden to fit preprocessing pipelines on the complete dataset prior to splitting.
**All preprocessing (e.g., scaling, imputation, encoding) must be fitted exclusively on the relevant training partition/fold.**

## 7.7 Missing Values

**Rule:** Missing values represent semantic absence.
* Missing values must **not** be arbitrarily converted to zero.
* Missing fingerprints must **not** be fabricated.
* For fingerprint experiments, a missing JA3 remains missing, and a missing JA4 remains missing.
* Rows that cannot support a fingerprint experiment (i.e., missing the required fingerprint) must be explicitly handled (e.g., dropped for fingerprint-specific evaluations). The exact handling mechanism must be documented and reproducible.

The final imputation strategy for flow features is currently unresolved.
**STATUS:** `PENDING_PHASE_7_STEP_2_OR_STEP_3_DECISION`

## 7.8 Scaling

**Rule:** Scaling must be fitted exclusively on training data.

* **Correct Flow:**
  1. Group-aware split
  2. Isolate training fold
  3. `fit` scaler on training fold
  4. `transform` training fold
  5. `transform` validation/test fold
* **Forbidden Flow:**
  * Entire dataset -> `fit_transform` -> split.

**Justification:** Fitting on the entire dataset leaks the global distribution (mean, variance, min/max) of the validation and test sets into the training process, providing the model with illicit future knowledge and artificially boosting performance.

## 7.9 Class Imbalance

**Current Imbalance:**
* 2,543 MALICIOUS
* 6 BENIGN_VALIDATION

While techniques such as class weighting, SMOTE, other training-only resampling, or controlled downsampling may be evaluated in subsequent steps, **NO technique is declared the final solution during Step 1.**

**Critical Rule:** Any resampling (oversampling or undersampling) must happen **INSIDE THE TRAINING FOLD ONLY.** Validation and test partitions must remain completely untouched.

**Caution:** Synthetic oversampling (e.g., SMOTE) does not create independent, real-world benign evidence; it merely interpolates existing data points and cannot replace actual large-scale benign captures.

## 7.10 Evaluation Metrics

**Primary Metrics:**
* PR-AUC (Precision-Recall Area Under Curve)
* Precision
* Recall
* F1-Score
* Balanced Accuracy

**Secondary Metrics:**
* ROC-AUC
* Specificity
* Confusion Matrix

**Note on Accuracy:** Raw accuracy is explicitly rejected as a primary metric due to the severe class imbalance (e.g., predicting the majority class would yield >99% accuracy but a completely useless model).

## 7.11 Reproducibility

Every future experiment must explicitly record:
1. Random seed
2. Dataset version
3. Feature version
4. Experiment configuration (A, B, C, D, E)
5. Grouping strategy
6. Preprocessing configuration
7. Missing-value strategy
8. Resampling strategy
9. Model configuration
10. Evaluation metrics
11. Python version
12. Relevant library versions

Future outputs must include machine-readable result artifacts.

## 7.12 Statistical Interpretation Rules

A high score on this current corpus does **NOT** automatically demonstrate general-purpose encrypted-traffic threat detection.

All results must be interpreted strictly within the context of:
* Extreme class imbalance.
* Six benign validation flows.
* Severe dataset-source confounding.
* Repeated behavioral structures.
* Limited fingerprint coverage (only 200 JA4 fingerprints).
* Possible capture-environment artifacts.

No result should ever be described as universally generalizable without external validation against an independent dataset.

## 7.13 Phase 7 Experimental Order

The Phase 7 roadmap is frozen as follows:

* **STEP 1: Experimental methodology lock (CURRENT)**
* **STEP 2:** Statistical/data audit
* **STEP 3:** Leakage-safe preprocessing
* **STEP 4:** Classical baseline models
* **STEP 5:** A–E experiments
* **STEP 6:** Group-aware cross-validation
* **STEP 7:** Ablation/fusion analysis
* **STEP 8:** Dataset-source confounder analysis
* **STEP 9:** Robustness/external validation
* **STEP 10:** Final statistical evaluation and research conclusions
