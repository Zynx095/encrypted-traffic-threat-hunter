# ETTH Dataset Evidence Verification Plan

## 1. Purpose
The Encrypted Traffic Threat Hunter (ETTH) is a scientific investigation aiming to determine whether combining TLS fingerprint features with flow behavioral features improves detection. If the underlying datasets used for experiments do not actually contain the required information (e.g., no valid ClientHello, severe leakage, missing labels), any resulting machine learning metrics will be invalid or misleading. Therefore, before selecting any dataset, ETTH requires a formal framework to verify that the dataset contains the necessary empirical evidence to support the intended experiments.

## 2. Verification Philosophy
The verification philosophy strictly separates documentary claims from empirical evidence. A dataset claiming to contain "TLS traffic" in its documentation (Level 0 evidence) cannot be treated as possessing computable JA4 fingerprints until raw PCAPs have been downloaded and successfully processed through an extractor (Level 2/3 evidence). Until an attribute is empirically proven, its state must remain NOT_VERIFIED.

## 3. Verification Levels
- **LEVEL 0 — DOCUMENTATION VERIFICATION:** Evidence derived from official websites, original papers, official repositories, or institutional repositories. Establishes stated characteristics like publication year, stated size, stated protocol coverage, stated labels, stated capture environment, stated licensing/access, and stated availability of raw files, but does NOT prove empirical properties.
- **LEVEL 1 — FILE / PCAP VERIFICATION:** Requires inspection of actual downloadable data. Verifies that raw PCAPs exist, can be opened, are not corrupted, and traffic is bidirectional where required. Can confirm packet counts, capture duration, TLS traffic presence, and basic protocol distribution.
- **LEVEL 2 — TLS / FINGERPRINT VERIFICATION:** Requires packet-level inspection. Verifies the presence of ClientHello, ServerHello, TLS versions, cipher suites, TLS extensions, signature algorithms, SNI, ALPN, and computability of JA3, JA3S, and JA4.
- **LEVEL 3 — FLOW FEATURE VERIFICATION:** Requires actual feature extraction. Verifies bidirectional flow construction, packet lengths, packet direction, packet counts, flow duration, inter-arrival times, burst/idle characteristics, bidirectional statistics, and the extraction of JA3/JA3S/JA4 hashes.
- **LEVEL 4 — EXPERIMENTAL SUITABILITY:** Requires analysis of extracted data. Verifies the percentage of encrypted flows, benign flow count, malware flow count, C2 flow count, class balance, application/family distribution, temporal distribution, duplicate flows, missing values, leakage, feature availability, train/validation/test feasibility, and cross-dataset compatibility.

IMPORTANT: Level 0 evidence must NEVER be treated as equivalent to Level 2 or Level 3 empirical verification.

## 4. Dataset Acceptance Logic
A dataset's acceptance is experiment-specific.
- **Flow-only:** Requires valid bidirectional flow construction, sufficient behavioral features (IAT, packet lengths, packet counts), and usable labels. JA3/JA4 computability is not required.
- **JA3-only:** Requires raw PCAP, ClientHello, ServerHello, successful JA3 and JA3S extraction, and usable labels. Flow feature computability is not required.
- **JA4-only:** Requires raw PCAP, ClientHello, ServerHello, successful JA4 and JA4S extraction conforming to the standard, and usable labels. Flow feature computability is not required.
- **JA3 + Flow:** Requires all JA3-only and Flow-only criteria, correctly linked by flow identity without leakage.
- **JA4 + Flow:** Requires all JA4-only and Flow-only criteria, correctly linked by flow identity without leakage.
- **Cross-dataset validation:** Requires features common across multiple datasets and well-documented temporal/environmental capture details to prevent models learning environmental artifacts.
- **Benign false-positive evaluation:** Requires a large and diverse representation of verified benign traffic, accurately labeled, with verified extraction of either Flow or Fingerprint features.

## 5. Dataset-by-Dataset Verification Plan

### DS-001 / ISCXVPN2016
### Current Registry Status
PARTIALLY_VERIFIED
### Evidence Currently Available
Documentation (Level 0), Flow Features (Level 3 via previously published CSVs).
### Claims Not Yet Independently Verified
ClientHello/ServerHello presence, JA3/JA4 computability.
### Required Evidence
Raw PCAP inspection for ClientHello/ServerHello, JA4 extraction testing.
### Verification Level Required
Level 2 & 3.
### Verification Method
Download sample PCAPs, filter for TLS, run JA3/JA4 extractors.
### Expected Output
Valid JA3/JA4 hashes for a non-trivial subset of flows.
### Acceptance Condition
JA4 computable on sample PCAPs.
### Rejection Condition
No valid ClientHello records or extraction fails (dataset becomes NOT_SUPPORTED for fingerprinting).
### Possible ETTH Role
LEGACY_COMPARISON; FLOW_ONLY_SUPPLEMENT.
### Priority
P1

### DS-002 / CIC-Darknet2020
### Current Registry Status
PARTIALLY_VERIFIED
### Evidence Currently Available
CSV features only (Level 3).
### Claims Not Yet Independently Verified
None regarding raw PCAP (known absent).
### Required Evidence
None for fingerprinting (rejected); CSV validation for flow features.
### Verification Level Required
Level 4 (for flow validity and class balance).
### Verification Method
Analyze CSV for leakage and class balance.
### Expected Output
Documented flow limitations and class imbalance ratios.
### Acceptance Condition
Sufficient usable flows for a Flow-only baseline.
### Rejection Condition
Irresolvable IP/port leakage dominating classification.
### Possible ETTH Role
FLOW_ONLY_SUPPLEMENT.
### Priority
P3

### DS-003 / USTC-TFC2016
### Current Registry Status
PARTIALLY_VERIFIED
### Evidence Currently Available
Raw PCAP availability (Level 1), Documentation (Level 0).
### Claims Not Yet Independently Verified
JA3/JA4 computability, actual encrypted flow percentage, modern TLS coverage.
### Required Evidence
ClientHello/ServerHello presence, successful JA3/JA4 extraction, post-filtering class balance.
### Verification Level Required
Level 2, 3 & 4.
### Verification Method
Download PCAP samples, run JA3/JA4 extractors, analyze filtered encrypted flow ratios.
### Expected Output
Valid JA3/JA4 hashes and sufficient malicious/benign balance after non-TLS traffic is removed.
### Acceptance Condition
JA4 successfully computable and sufficient class representation after filtering.
### Rejection Condition
High unencrypted ratio leaves too few TLS flows, or JA4 fails to extract.
### Possible ETTH Role
PRIMARY_TRAINING; PRIMARY_TEST.
### Priority
P0

### DS-004 / CipherSpectrum
### Current Registry Status
PENDING
### Evidence Currently Available
Mentions in related work (Level 0).
### Claims Not Yet Independently Verified
Access availability, raw PCAP availability, all TLS/Flow features.
### Required Evidence
Proof of access and downloadable raw PCAP.
### Verification Level Required
Level 1.
### Verification Method
Attempt to access or request the dataset from authors.
### Expected Output
Accessible raw PCAPs or formal rejection/paywall.
### Acceptance Condition
Unrestricted or obtainable research access to PCAPs.
### Rejection Condition
Access denied or requires payload decryption.
### Possible ETTH Role
MODERN_TLS_VALIDATION.
### Priority
P0

### DS-005 / CSTNET-TLS1.3
### Current Registry Status
PENDING
### Evidence Currently Available
Mentions in related work (Level 0).
### Claims Not Yet Independently Verified
Access availability, all technical aspects.
### Required Evidence
Proof of existence and accessibility.
### Verification Level Required
Level 1.
### Verification Method
Locate official source and attempt download.
### Expected Output
Accessible raw PCAPs.
### Acceptance Condition
Obtainable PCAPs with TLS 1.3 traffic.
### Rejection Condition
Dataset unavailable or inaccessible.
### Possible ETTH Role
MODERN_TLS_VALIDATION.
### Priority
P0

## 6. Technical Verification Requirements
Every candidate must eventually be assessed for:

RAW DATA:
- Raw PCAP availability
- PCAP readability
- Bidirectional traffic

TLS:
- TLS traffic
- TLS 1.2
- TLS 1.3
- QUIC where applicable

HANDSHAKES:
- ClientHello
- ServerHello

FINGERPRINTS:
- JA3
- JA3S
- JA4
- JA4S where relevant

FLOW FEATURES:
- packet lengths
- packet direction
- packet counts
- flow duration
- IAT
- burst characteristics
- bidirectional statistics

LABELS:
- benign
- malware
- C2
- application labels
- malware family labels
- label quality

RESEARCH VALIDITY:
- capture environment
- temporal information
- class balance
- duplicate traffic
- IP leakage
- port leakage
- SNI leakage
- timestamp leakage
- dataset-source leakage
- malware-family leakage

## 7. Experiment-Specific Acceptance Rules
A dataset can be unsuitable for JA4 but still useful for flow-only experiments.

A dataset may support JA4 experiments ONLY IF:
1. Raw PCAP is available.
2. ClientHello exists.
3. Required JA4 fields can be extracted.
4. Extraction succeeds on representative samples.
5. Generated fingerprints are validated against the selected authoritative implementation.

JA4 + Flow requires:
- JA4 successfully computed
- valid flow construction
- packet lengths
- IAT
- usable labels
- leakage controls

Flow-only requires:
- valid flow construction
- sufficient behavioral features
- usable labels

Scientific Justification: JA4 requires exact byte sequences and protocol-specific fields that are lost in pre-extracted CSV representations. Therefore CSV-only datasets are immediately rejected for JA4 (NOT_SUPPORTED) but may be POSSIBLY_SUPPORTED for Flow-only baselines. Flow behavior requires bidirectional timing, making single-sided captures unsuitable. Label validity and leakage controls are universally required for robust machine learning, preventing the model from learning environmental artifacts instead of traffic behavior.

## 8. Verification Matrix

| Dataset | Raw PCAP | Bidirectional | ClientHello | ServerHello | JA3 | JA3S | JA4 | Flow | TLS 1.3 | Malware | Labels | Leakage | Required Level | Priority |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| DS-001 | VERIFIED_YES | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | VERIFIED_YES | VERIFIED_NO | VERIFIED_NO | PARTIALLY_VERIFIED | PARTIALLY_VERIFIED | 3 | P1 |
| DS-002 | VERIFIED_NO | NOT_APPLICABLE | VERIFIED_NO | VERIFIED_NO | VERIFIED_NO | VERIFIED_NO | VERIFIED_NO | VERIFIED_YES | NOT_APPLICABLE | VERIFIED_NO | PARTIALLY_VERIFIED | PARTIALLY_VERIFIED | 4 | P3 |
| DS-003 | VERIFIED_YES | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | VERIFIED_YES | VERIFIED_NO | VERIFIED_YES | PARTIALLY_VERIFIED | PARTIALLY_VERIFIED | 4 | P0 |
| DS-004 | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | VERIFIED_YES | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | 1 | P0 |
| DS-005 | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | VERIFIED_YES | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | 1 | P0 |

## 9. Evidence Chains
**JA4 COMPUTABILITY**
Official dataset documentation -> Raw PCAP confirmed -> ClientHello confirmed -> Required JA4 fields extracted -> JA4 extraction executed -> Output validated -> JA4 marked VERIFIED.

**JA3 COMPUTABILITY**
Official dataset documentation -> Raw PCAP confirmed -> ClientHello confirmed -> Required JA3 fields extracted -> JA3 extraction executed -> Output validated -> JA3 marked VERIFIED.

**JA3S COMPUTABILITY**
Official dataset documentation -> Raw PCAP confirmed -> ServerHello confirmed -> Required JA3S fields extracted -> JA3S extraction executed -> Output validated -> JA3S marked VERIFIED.

**FLOW FEATURES**
Official dataset documentation -> Raw PCAP/CSV confirmed -> Bidirectional traffic confirmed -> Timestamps & packet sizes confirmed -> Flow reconstruction executed -> Output validated -> Flow features marked VERIFIED.

**TLS 1.3 COVERAGE**
Official dataset documentation -> Raw PCAP confirmed -> ClientHello confirmed -> Supported Versions extension parsed -> TLS 1.3 records counted -> Output validated -> TLS 1.3 marked VERIFIED.

**MALWARE LABELS**
Official dataset documentation -> Label mapping provided -> Flow identification mapped to labels -> Label quality methodology verified -> Malware labels marked VERIFIED.

**C2 LABELS**
Official dataset documentation -> C2 label mapping provided -> Flow identification mapped to C2 framework labels -> C2 labels marked VERIFIED.

**ENCRYPTED-FLOW PERCENTAGE**
Raw PCAP confirmed -> Traffic filtering applied (TLS only) -> Encrypted flows counted -> Percentage derived -> Encrypted-flow percentage marked VERIFIED.

## 10. Future Sample-Based Verification
To verify datasets efficiently without processing terabytes of data initially, a sample-based verification methodology will be used:
1. Select a stratified random sample of 10 PCAP files (or up to 1GB of data) covering both benign and malware traffic (if segregated by file).
2. Ensure the sample captures multiple malware families or applications if such metadata is available.
3. Perform Level 2 and Level 3 extraction solely on the sample.
4. If the sample yields a sufficient density of valid JA4 hashes and flow features (e.g., >50% of TLS flows successfully parse), proceed to full dataset processing.
5. If the sample reveals catastrophic flaws (e.g., all payloads truncated, zero ClientHellos, corrupt headers), reject the dataset for JA4 experiments immediately.

*Note: This is a planned verification sample. The statistical sufficiency of the sample size will be evaluated after the initial test proves empirical validity.*

## 11. Rejection Conditions
A dataset should be rejected FOR A PARTICULAR EXPERIMENT if:
- required raw information is absent
- ClientHello is unavailable for JA4
- required fingerprint fields cannot be extracted
- labels are unreliable
- encrypted traffic is insufficient
- severe leakage cannot be controlled
- PCAPs cannot be parsed
- required flow features cannot be reconstructed
- the dataset cannot support the intended experimental comparison

Dataset rejection must be experiment-specific where possible. Do not unnecessarily discard a dataset that remains useful for another research purpose (e.g., Flow-only evaluation).

## 12. Most Important Unresolved Question
The single most important unresolved dataset question for ETTH is:
**Does DS-003 (USTC-TFC2016) contain computable JA4 fingerprints and a sufficient volume of TLS-encrypted traffic after filtering out its reported 94.7% unencrypted traffic?**

*Reasoning:* DS-003 is currently the ONLY dataset in the registry that provides verifiable raw PCAPs containing both benign and malware traffic. If DS-003 fails JA4 extraction or yields too few encrypted flows after filtering, the project currently has NO dataset capable of supporting the primary JA4 + Flow malicious detection experiment (Experiments C and E). CipherSpectrum and CSTNET-TLS1.3 remain inaccessible unknowns. The viability of the entire experimental design rests entirely on the empirical validation of DS-003.
