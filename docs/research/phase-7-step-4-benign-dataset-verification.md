# Phase 7 Step 4 — Benign Dataset Empirical Verification

## 1. Objective
Empirically verify candidate datasets capable of providing independent BENIGN encrypted traffic. The objective is to determine if a candidate can supply raw PCAPs, legitimate modern TLS traffic, JA3/JA4 computability, and independent environmental provenance to address the critical 424:1 class imbalance and DS-008 vs DS-004 source confounding.

## 2. Candidate Selection
Based on the Custom Data Acquisition Plan (Step 3), the following high-priority benign candidates were selected for verification:
1. **CIRA-CIC-DoHBrw-2020** (CAND-008)
2. **CIC-IDS-2017** (CAND-006)

## 3. Source Provenance & Access
- **CIRA-CIC-DoHBrw-2020**: Published by the Canadian Institute for Cybersecurity (UNB).
- **CIC-IDS-2017**: Published by the Canadian Institute for Cybersecurity (UNB).
- **License/Access**: Both datasets require the user to fill out a "CIC DATASET DOWNLOAD FORM" providing PII and accepting an academic usage license before a download link is generated.

## 4. Empirical Verification Findings
As dictated by the strict prohibition against bypassing access controls, automated retrieval of the datasets via the pipeline was impossible.
- **Downloaded Artifacts**: None.
- **SHA-256 Hashes**: `UNKNOWN` (No files downloaded).
- **PCAP Validation**: `NOT_VERIFIED`
- **Flow Reconstruction**: `UNKNOWN`
- **TLS & Fingerprint Statistics**: `UNKNOWN`
- **Label Validation**: `UNCERTAIN`. Since the data could not be parsed, the exact labeling mechanics at the flow level cannot be verified.
- **Source-Environment Analysis**: Expected to be a simulated network environment (UNB lab), which would provide excellent independent baseline traffic compared to `CipherSpectrum` (DS-004), but cannot be empirically tested at this time.
- **Duplicate/Overlap Analysis**: `NOT_VERIFIED`

## 5. Admission/Rejection Decision
**Decision:** `REJECTED` (for both CAND-008 and CAND-006).
**Reason:** The datasets are inaccessible to the automated pipeline due to mandatory registration forms and license agreements. They cannot be technically obtained without manual user intervention or bypassing access controls.

## 6. Limitations
Because the highest-priority academic benign datasets are gated behind registration, the automated pipeline cannot independently solve the class imbalance problem.

## 7. Recommendation
To proceed, a human researcher must manually register, accept the license agreements, download the PCAPs for a selected dataset (e.g., CIRA-CIC-DoHBrw-2020), and place a representative subset into `data/verification/pcaps/`. Once the data is manually provisioned, this automated empirical verification step can be successfully re-run.
