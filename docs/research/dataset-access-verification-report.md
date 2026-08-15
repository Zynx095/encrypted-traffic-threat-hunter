# Dataset Access Verification Report

**Date:** 2026-08-15
**Phase:** 5
**Step:** 13
**Status:** COMPLETE

## 1. Objective
Determine whether the highest-priority dataset candidates are actually accessible for ETTH research. The primary requirement is obtaining enough representative raw network traffic (PCAPs) to independently verify ClientHello, ServerHello, JA3, JA3S, JA4, and encrypted-flow features.

## 2. Access Verification Methodology
- Targeted web search for official repositories, dataset release records (e.g., Zenodo), and author communications.
- Explicit distinction between "dataset exists", "extracted features are public", and "raw PCAP is public".
- Identification of specific access barriers and procedures.

---

## 3. DS-006: Beyond JA4+ Dataset
- **Access Status:** `ACADEMIC_REQUEST_REQUIRED` (Full PCAP), `PUBLICLY_DOWNLOADABLE` (Subset/Scripts)
- **Official Dataset/Repository URL:** https://github.com/matousp/tls-fingerprinting, https://github.com/matousp/malware-analysis
- **Raw PCAP Availability:** Restricted. The public repositories contain a subset of sample PCAPs and feature extraction code. The full dataset is restricted to academic requests.
- **Feature Data Availability:** `PUBLICLY_DOWNLOADABLE`. Precomputed statistics and JA3/JA4 data exist, but cannot substitute for independent verification.
- **Academic Request:** Required. Must contact Petr Matoušek (Brno University of Technology) at `matousp@fit.vutbr.cz`.
- **License/Constraints:** Academic use.
- **Teacher/Institutional Assistance Required:** `YES`.
- **Recommended Action:** Draft academic request; wait for access before proceeding with DS-006 verification.

---

## 4. DS-007: Annotated Encrypted Network Traffic Dataset
- **Access Status:** `ACADEMIC_REQUEST_REQUIRED` (Raw PCAP), `PUBLICLY_DOWNLOADABLE` (Parquet Features)
- **Official Dataset/Repository URL:** https://zenodo.org/ (Ondřej Ryšavý, Brno University of Technology)
- **Raw PCAP Availability:** Restricted. The Zenodo metadata explicitly states that raw PCAP files are available "upon justified request".
- **Feature Data Availability:** `PUBLICLY_DOWNLOADABLE`. 1.0.0 release contains extracted features in Parquet format.
- **Academic Request:** Required.
- **License/Constraints:** Academic use.
- **Teacher/Institutional Assistance Required:** `YES`.
- **Recommended Action:** Draft academic request; wait for access before proceeding with DS-007 verification.

---

## 5. DS-008: Malware-Traffic-Analysis.net (MTA)
- **Access Status:** `PUBLICLY_DOWNLOADABLE`
- **Official Dataset/Repository URL:** https://www.malware-traffic-analysis.net/
- **Raw PCAP Availability:** `PUBLICLY_DOWNLOADABLE`. Individual PCAPs corresponding to specific malware exercises are directly available without registration.
- **TLS Malware Samples:** Excellent. Recent (2024-2025) captures with modern TLS 1.3 C2 traffic exist.
- **Benign Data:** None.
- **Small-Sample Availability:** Yes. Individual PCAPs (often < 10MB) can be downloaded directly.
- **Recommended Action:** Proceed immediately to empirical JA4 verification using a small 2024-2025 TLS 1.3 PCAP sample from MTA.

---

## 6. DS-009: Stratosphere Malware Capture Facility Project (MCFP)
- **Access Status:** `PUBLICLY_DOWNLOADABLE`
- **Official Dataset/Repository URL:** https://www.stratosphereips.org/datasets-overview
- **Raw PCAP Availability:** `PUBLICLY_DOWNLOADABLE`.
- **TLS Coverage:** Mixed. Many historical captures use older TLS. Modern captures must be explicitly filtered.
- **Small-Sample Availability:** Yes. Individual capture folders can be accessed and downloaded selectively.
- **Recommended Action:** Filter repository for recent captures and proceed to empirical JA4 verification.

---

## 7. Access Comparison Table

| Dataset | Access Status | Raw PCAP | Feature Data | Requires Request |
|---------|---------------|----------|--------------|------------------|
| DS-006 | `ACADEMIC_REQUEST_REQUIRED` | RESTRICTED | PUBLIC | YES |
| DS-007 | `ACADEMIC_REQUEST_REQUIRED` | RESTRICTED | PUBLIC (Parquet) | YES |
| DS-008 | `PUBLICLY_DOWNLOADABLE` | PUBLIC | N/A | NO |
| DS-009 | `PUBLICLY_DOWNLOADABLE` | PUBLIC | N/A | NO |

## 8. Remaining Unknowns
- Will the academic requests for DS-006 and DS-007 be granted to a student researcher?
- How long will the approval process take?
- Are the specific TLS 1.3 PCAPs from DS-008 structurally sound enough for the ETTH JA4 extraction script?

## 9. Step 14 Recommendation
Do not wait idly for DS-006/DS-007 access. Immediately initiate Step 14: **Empirical Candidate PCAP Verification** using a targeted, small sample from **DS-008 (MTA)**. This will prove definitively whether modern malware C2 TLS 1.3 traffic is technically JA4-computable in practice.
