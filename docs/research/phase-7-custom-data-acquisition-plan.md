# Phase 7 — Custom Data Acquisition Plan

## 1. Objective
Establish a reproducible, auditable workflow for discovering and onboarding additional legitimate public network-traffic datasets and malware-traffic PCAP sources.

## 2. Scientific Motivation
The current model-safe dataset suffers from two critical limitations:
1. **Severe Class Imbalance**: 2,543 MALICIOUS flows vs 6 BENIGN_VALIDATION flows.
2. **Dataset-Source Confounding**: All malicious data stems from a single source (Malware-Traffic-Analysis.net) and all benign data from another (CipherSpectrum).
Acquiring high-quality, modern BENIGN traffic and diverse MALICIOUS traffic is necessary to enable scientifically valid Phase 7 machine learning experiments.

## 3. Source-Selection Criteria
Candidates are ranked primarily by their ability to provide:
1. Legitimate benign TLS traffic.
2. Modern TLS 1.2 / TLS 1.3 traffic.
3. Raw PCAPs (for independent flow and TLS fingerprint reconstruction).
4. Multiple independent capture environments.
5. Sufficient volume to balance existing datasets.
6. Useful labels.
7. Independent source provenance.

## 4. Allowed Source Types
- Downloadable PCAP archives.
- Network-traffic datasets with raw packet data.
- Datasets explicitly suitable for independent TLS/JA3/JA4 extraction.
- Formal academic datasets (e.g., CIC, Stratosphere).

## 5. Disallowed Source Types
- Webpages only describing malware.
- Webpages or repositories only containing Indicators of Compromise (IOCs).
- Datasets containing only pre-extracted CSV features without raw PCAPs (preventing JA3/JA4 extraction).
- Synthetic traffic fabricated to simulate real traffic.

## 6. Licensing/Access Requirements
- Only free, publicly accessible, or legitimately requestable academic datasets are permitted.
- No paywalls, bypassing of authentication/CAPTCHAs, or unauthorized website exploitation.

## 7. PCAP Validation Requirements
- The source must provide raw PCAP or PCAPNG files.
- The files must open successfully in tools like Wireshark/tshark without severe corruption.

## 8. TLS Validation Requirements
- The traffic must contain TLS handshakes (ClientHello/ServerHello).
- Datasets comprised only of plain HTTP, UDP floods, or non-TLS malware C2 are disqualified for fingerprint experiments.

## 9. Label Validation Requirements
- Labels must be provided at the flow, IP, or PCAP level clearly distinguishing Malicious from Benign behavior.

## 10. Provenance Requirements
- The original source, download URL, capture environment, and date must be fully recorded to control for confounding variables.

## 11. Dataset-Source Leakage Controls
- Source environment traits (e.g., specific IPs, MACs, MTA filenames) must be explicitly stripped from ML features.

## 12. Raw-Data Storage Rules
- Raw PCAPs must be stored in `data/raw/` or `data/verification/pcaps/` according to standard project conventions.
- Large PCAPs must not be committed to Git.

## 13. Git Safety Rules
- Comply with `.gitignore`.
- NEVER commit raw `.pcap`, `.pcapng`, `.zip`, `.tar.gz` files.
- Do not modify `.gitignore` to force raw datasets into Git.

## 14. Candidate Admission/Rejection Criteria
- **Admit**: Raw PCAP available, TLS present, labels available, license is open/academic, significantly adds to benign traffic volume or malicious source diversity.
- **Reject**: Only IOCs available, no raw PCAP, only HTTP traffic, paid access only.

## 15. Reproducibility Requirements
- Every dataset evaluated must have a formal entry in `docs/research/custom-dataset-candidate-registry.csv`.
