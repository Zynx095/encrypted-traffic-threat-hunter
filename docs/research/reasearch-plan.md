# ETTH Research Plan

## Encrypted Traffic Threat Hunter (ETTH)

**Project Type:** Undergraduate Research Project  
**Domain:** Computer Networks, Network Security, Encrypted Traffic Analysis, Machine Learning  
**Research Level:** Third-Year B.Tech / Undergraduate Research  
**Current Stage:** Research Foundation and Dataset Investigation

---

## 1. Project Overview

The **Encrypted Traffic Threat Hunter (ETTH)** is a research project focused on detecting suspicious or malicious network communication without decrypting the application payload.

Modern network traffic is increasingly protected by TLS 1.2, TLS 1.3, and newer encrypted protocols. Traditional payload inspection becomes less useful when the actual application data cannot be directly observed.

ETTH therefore studies whether useful security information can still be extracted from **metadata that remains observable during encrypted communication**.

The project will investigate two main feature families:

1. **TLS fingerprint features**
   - JA3
   - JA3S
   - JA4
   - TLS version
   - Cipher-suite information
   - TLS extensions
   - ALPN
   - SNI-related information where legally and technically available

2. **Encrypted-flow behavioral features**
   - Flow duration
   - Packet count
   - Bytes sent and received
   - Packet-size distributions
   - Inter-arrival times
   - Traffic directionality
   - Burst and idle behavior
   - Other defensible flow-level metadata

The objective is not to decrypt the traffic. The objective is to determine whether **observable metadata can provide reliable and explainable evidence of malicious communication**.

---

# 2. Research Problem

Malware and other malicious applications increasingly communicate through encrypted channels.

This creates a problem for network defenders:

> How can malicious encrypted communication be detected when the payload itself cannot be inspected?

TLS fingerprints can provide information about the software or TLS implementation initiating a connection. However, fingerprints can also be shared by completely different applications because many legitimate and malicious programs use the same cryptographic libraries.

Flow-level behavior provides another source of information through packet sizes, timing, directionality, and communication patterns.

The research problem is therefore to determine whether these two sources of metadata provide complementary information.

---

# 3. Primary Research Question

> **Does combining TLS fingerprint features (JA4/JA3S) with encrypted-flow behavioral features provide a statistically significant improvement in malicious-traffic detection compared with using either feature family independently?**

---

# 4. Research Hypotheses

### Null Hypothesis — H0

There is no statistically significant difference in detection performance between:

- Flow-only
- JA4-only
- Combined JA4 + Flow

configurations.

### Alternative Hypothesis — H1

The combined **JA4 + Flow** configuration provides a statistically significant improvement in detection performance compared with the individual feature families.

The project will treat a null result as a valid scientific result.

If feature fusion does not improve performance, that result will still provide useful evidence about the limitations of combining TLS fingerprints with flow behavior.

---

# 5. Research Objectives

## Objective 1 — Understand the Existing Research

Perform a structured literature review covering:

- Encrypted traffic analysis
- TLS fingerprinting
- JA3 and JA3S
- JA4 and JA4+
- Flow-based intrusion detection
- Malware/C2 detection
- Machine learning for network security
- Explainable AI
- Dataset bias
- Concept drift
- TLS 1.3
- Encrypted Client Hello (ECH)

---

## Objective 2 — Identify Suitable Datasets

Investigate datasets that contain:

- Raw PCAP traffic
- Modern encrypted traffic
- TLS handshakes
- Benign traffic
- Malicious or malware/C2 traffic
- Sufficient information for JA3/JA3S/JA4 extraction
- Sufficient information for flow-level feature extraction

Dataset selection will be treated as a research decision rather than simply choosing the largest available dataset.

---

## Objective 3 — Verify JA3/JA4 Computability

Before using a dataset, verify whether the required packet information is actually present.

In particular, verify the availability of:

- ClientHello
- ServerHello
- Cipher suites
- TLS extensions
- Signature algorithms where required
- ALPN
- SNI-related fields
- Bidirectional traffic

A dataset containing TLS traffic will **not automatically be considered JA4-compatible**.

---

## Objective 4 — Build a Reproducible Traffic-Extraction Pipeline

Develop a controlled pipeline for converting PCAP traffic into research features.

Conceptually:

```text
PCAP
  ↓
Packet Parsing
  ↓
TLS Handshake Extraction
  ↓
JA3 / JA3S / JA4 Extraction
  ↓
Flow Construction
  ↓
Flow Behavioral Features
  ↓
Feature Validation
  ↓
Research Dataset
```

The exact implementation tools will be selected only after dataset verification.

---

## Objective 5 — Construct Controlled Experimental Configurations

The initial comparison will contain five configurations:

| Configuration | Features |
|---|---|
| A | Flow-only |
| B | JA3-only |
| C | JA4-only |
| D | JA3 + Flow |
| E | JA4 + Flow |

This structure allows the contribution of each feature family to be evaluated separately.

---

# 6. Experimental Methodology

## 6.1 Data Preparation

Raw PCAP data will be processed into flow-level records.

The preprocessing stage will include:

- Flow identification
- Direction identification
- TLS handshake extraction
- TLS fingerprint extraction
- Flow-statistic extraction
- Label assignment
- Feature validation
- Duplicate detection
- Missing-value analysis

---

## 6.2 Leakage Prevention

Special attention will be given to features that can allow a model to obtain the answer without learning meaningful traffic behavior.

Potential leakage sources include:

- SNI
- IP addresses
- Domain names
- Destination ports
- Capture-environment identifiers
- Dataset-specific artifacts
- Timestamp-related artifacts
- Duplicate or near-duplicate flows

The experiment will explicitly document which features are removed, transformed, or retained and why.

---

## 6.3 Data Splitting

The project will avoid naive packet-level random splitting.

Possible evaluation strategies include:

- Flow-level splitting
- Application-level splitting
- Malware-family-level splitting
- Temporal splitting
- Cross-dataset validation

The final strategy will be selected after examining the structure of the chosen datasets.

---

# 7. Machine Learning Methodology

Initial candidate models will include:

- Random Forest
- XGBoost

These models are suitable starting points because they work well with structured tabular network features and provide useful feature-importance information.

More complex models will only be introduced if there is a clear research reason.

The project will avoid adding deep-learning architectures merely to make the project appear more advanced.

---

# 8. Evaluation Metrics

Model evaluation will not rely only on accuracy.

Primary metrics will include:

- Precision
- Recall
- F1-score
- False Positive Rate (FPR)
- False Negative Rate (FNR)
- ROC-AUC
- PR-AUC
- Confusion Matrix

Where appropriate, results will include:

- 95% confidence intervals
- Statistical significance tests
- Effect sizes

Potential statistical methods include:

- Bootstrap confidence intervals
- McNemar's test for paired classification outcomes
- DeLong-type comparisons for ROC-AUC where appropriate

The final statistical procedure will depend on the exact experimental setup and data assumptions.

---

# 9. Explainability

The project will investigate whether model decisions can be explained to a network-security analyst.

The initial explainability method is:

**SHAP (SHapley Additive exPlanations)**

The analysis will investigate:

- Which features influence predictions
- Whether JA4 contributes meaningful information
- Whether flow features dominate decisions
- Whether different feature families provide complementary evidence
- Whether explanations remain stable across datasets

Explainability will be treated as part of the research evaluation rather than simply a dashboard feature.

---

# 10. Dataset Strategy

The current research indicates that a single dataset may not satisfy every ETTH requirement.

The project will therefore distinguish between:

### Primary Dataset

A dataset containing:

- Modern encrypted traffic
- Benign traffic
- Malware/C2 traffic
- Raw PCAP
- JA3/JA4-compatible TLS handshakes
- Flow-level information

### Secondary Dataset

Used to investigate generalization beyond the primary collection environment.

### Validation Dataset

Used where appropriate to test robustness against:

- Different environments
- Different applications
- Different network conditions
- Different traffic distributions
- Protocol differences

The exact datasets will be finalized only after direct verification of availability, labels, PCAP contents, and JA4 computability.

---

# 11. Research Validity

The project will explicitly investigate the following threats to validity:

## Dataset Bias

A dataset may not represent modern real-world network traffic.

## Capture-Environment Bias

A model may learn characteristics of the laboratory or sandbox rather than malicious behavior.

## Class Imbalance

Malicious and benign traffic may not be equally represented.

## Fingerprint Collision

Different applications may share the same TLS fingerprint.

## Concept Drift

Network behavior and TLS implementations change over time.

## SNI Leakage

Models may learn malicious domain names instead of traffic behavior.

## IP/Port Leakage

Models may learn dataset-specific infrastructure instead of malicious behavior.

## Family Leakage

The same malware family appearing in training and testing can make performance appear artificially high.

## Protocol Evolution

TLS 1.3, ECH, QUIC, and HTTP/3 can change the observable information available to network defenders.

---

# 12. Research Phases

## Phase 1 — Research Foundation

**Status:** Completed

Tasks:

- Define research problem
- Establish research question
- Establish initial hypotheses
- Define project scope
- Identify initial literature areas
- Establish research documentation structure

Deliverables:

- Research foundation
- Research problem
- Research design documentation

---

## Phase 2 — Literature and Dataset Discovery

**Status:** Completed / Continuing

Tasks:

- Discover relevant academic literature
- Build literature corpus
- Verify sources
- Build evidence matrix
- Identify research gaps
- Discover candidate datasets

Deliverables:

- Literature corpus
- Literature matrix
- Annotated bibliography
- Dataset evaluation
- Cross-paper synthesis

---

## Phase 3 — Research Gap Validation

**Status:** Completed / Under refinement

Tasks:

- Compare ETTH against recent literature
- Identify overlapping work
- Identify limitations of existing studies
- Prevent accidental replication
- Refine the research contribution

Current direction:

The project should focus on rigorous evaluation of **feature fusion, leakage control, generalization, and explainability**, rather than simply claiming that JA4 + flow features have never been studied.

---

## Phase 4 — Experimental Design

**Status:** Completed

Tasks:

- Define independent variables
- Define dependent variables
- Define control variables
- Define experimental configurations
- Define evaluation metrics
- Define statistical evaluation
- Define scope limitations

Deliverables:

- Experimental variables
- Experimental design
- Research design summary

---

## Phase 5 — Dataset Evaluation

**Status:** Completed / Requires final verification

Tasks:

- Evaluate existing datasets
- Search for modern TLS datasets
- Search for malware/C2 datasets
- Check raw PCAP availability
- Check TLS version coverage
- Check JA3/JA4 computability
- Identify dataset leakage risks
- Identify dataset combinations

Current priority:

**Do not begin model training until the dataset strategy is experimentally verified.**

---

## Phase 6 — Direct Dataset Verification

**Next major phase**

Tasks:

1. Obtain candidate datasets.
2. Verify download and access conditions.
3. Inspect PCAP structure.
4. Verify TLS traffic.
5. Verify ClientHello availability.
6. Verify ServerHello availability.
7. Test JA3 extraction.
8. Test JA3S extraction.
9. Test JA4 extraction.
10. Verify flow reconstruction.
11. Measure TLS-version distribution.
12. Measure benign/malicious class distribution.
13. Identify duplicates.
14. Identify obvious leakage.
15. Document the final dataset decision.

**Gate:** No ML training before this phase is complete.

---

## Phase 7 — Data Extraction Pipeline

Tasks:

- Build reproducible PCAP processing
- Extract TLS metadata
- Extract JA3/JA3S/JA4
- Construct bidirectional flows
- Extract behavioral features
- Validate extracted features
- Create versioned datasets

Deliverable:

**ETTH Feature Extraction Pipeline**

---

## Phase 8 — Baseline Experiments

Run:

- Flow-only
- JA3-only
- JA4-only

Establish baseline performance before attempting feature fusion.

Deliverables:

- Baseline metrics
- Confusion matrices
- Feature statistics
- Initial error analysis

---

## Phase 9 — Feature Fusion Experiments

Run:

- JA3 + Flow
- JA4 + Flow

Compare against the baseline configurations.

Primary question:

> Does combining TLS fingerprint information with flow behavior provide measurable improvement?

---

## Phase 10 — Statistical Evaluation

Perform:

- Confidence interval estimation
- Paired model comparisons
- Significance testing
- Effect-size analysis
- Error analysis

The goal is to determine whether observed improvements are statistically meaningful rather than caused by random variation.

---

## Phase 11 — Explainability

Use SHAP or another justified XAI method to analyze:

- Global feature importance
- Per-flow explanations
- JA4 contribution
- Flow-feature contribution
- Model disagreement
- Explanation stability

---

## Phase 12 — Generalization and Robustness

Evaluate:

- Temporal generalization
- Malware-family generalization
- Cross-environment performance
- Cross-dataset performance
- Modern TLS performance
- Potential ECH-related degradation

---

## Phase 13 — Final Analysis

Analyze:

- Performance differences
- False positives
- False negatives
- Fingerprint collisions
- Dataset limitations
- Generalization failures
- Explainability results
- Statistical significance

The project will report negative findings honestly.

---

## Phase 14 — Research Paper

Final paper structure:

1. Abstract
2. Introduction
3. Background
4. Related Work
5. Research Gap
6. Research Questions and Hypotheses
7. Dataset Selection
8. Methodology
9. Feature Extraction
10. Experimental Design
11. Results
12. Statistical Analysis
13. Explainability
14. Generalization Analysis
15. Limitations
16. Discussion
17. Conclusion
18. Future Work
19. References

---

# 13. Expected Research Contribution

The intended contribution is **not** simply:

> "We built an ML model that detects malware."

Instead, ETTH aims to provide a controlled experimental study of:

> **How TLS fingerprint information and encrypted-flow behavioral information contribute individually and jointly to malicious encrypted-traffic detection, under strict leakage controls and cross-environment evaluation.**

The research will specifically investigate whether fingerprint information adds useful information beyond flow behavior, whether flow behavior compensates for fingerprint limitations, and whether the combination remains useful when network visibility changes.

---

# 14. Scope Boundaries

ETTH will not attempt to:

- Decrypt application payloads
- Replace a production SOC
- Guarantee malware identification
- Perform large-scale enterprise deployment
- Build a universal threat detector
- Claim that one ML model is universally superior
- Use deep learning without experimental justification
- Treat high accuracy as proof of research validity

---

# 15. Current Research Position

At the current stage:

```text
Research Foundation
        ↓
Literature Review
        ↓
Research Gap Validation
        ↓
Experimental Design
        ↓
Dataset Landscape
        ↓
[CURRENT POSITION]
        ↓
Direct Dataset Verification
        ↓
Feature Extraction
        ↓
Baseline Experiments
        ↓
Feature Fusion
        ↓
Statistical Evaluation
        ↓
Explainability
        ↓
Generalization
        ↓
Research Paper
```

The project is currently **before implementation and model training**.

The next scientific gate is to directly verify the candidate datasets and confirm that the required TLS handshake information, JA3/JA3S/JA4 inputs, flow information, labels, and modern encrypted traffic are actually available.

---

# 16. Research Principles

The project will follow these principles throughout development:

1. **Evidence before implementation.**
2. **Raw data before assumptions.**
3. **Reproducibility before optimization.**
4. **Statistical evidence before performance claims.**
5. **Leakage prevention before model training.**
6. **Negative results are valid results.**
7. **Dataset limitations must be documented.**
8. **Recent literature must be checked before claiming novelty.**
9. **No feature will be described as available unless it is verified.**
10. **No model will be considered successful merely because it achieves high accuracy.**

---

## 17. Immediate Next Step

**Phase 6 — Direct Dataset Verification**

Before writing the extraction pipeline or training any ML model, ETTH will verify the strongest candidate datasets directly.

The first verification targets will be:

1. Raw PCAP availability
2. TLS traffic presence
3. TLS version distribution
4. ClientHello availability
5. ServerHello availability
6. JA3 computability
7. JA3S computability
8. JA4 computability
9. Flow reconstruction
10. Benign/malicious label validity

Only after these checks pass will implementation begin.
