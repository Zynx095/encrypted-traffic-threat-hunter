# Expanded Dataset Evidence Register

**Date:** 2026-08-15
**Purpose:** Register the specific claims, evidence strength, and verification status for the expanded dataset candidates (DS-006 through DS-010) identified in Phase 5 Step 11.
**Companion Files:** `dataset-registry.csv`, `dataset-candidate-scorecard.md`

## Overview of Evidence Hierarchy
- **STRONG:** Official dataset documentation, original paper, official repository, directly downloadable raw PCAP.
- **MODERATE:** Peer-reviewed paper using the dataset, reproducible extraction repository.
- **WEAK:** Secondary articles, informal descriptions, dataset aggregators.
- **UNKNOWN:** No reliable evidence found.

---

## DS-006: Beyond JA4+ Dataset (Brno University)

| Claim | Status | Evidence Strength | Evidence Source | Source Type | Notes | Requires Empirical Verification |
|-------|--------|-------------------|-----------------|-------------|-------|---------------------------------|
| Contains malware and benign traffic | VERIFIED_YES | STRONG | Original dataset paper / GitHub Repo | Official Repository | Labeled samples exist in repository. | No (Existence verified) |
| Raw PCAPs are available | PARTIALLY_VERIFIED | STRONG | GitHub Repo (`matousp/tls-fingerprinting`) | Official Repository | Repository contains subset/samples of PCAPs. Full PCAPs require academic request. | Yes (Access required) |
| Modern TLS 1.3 present | VERIFIED_YES | STRONG | Original dataset paper | Peer-Reviewed Paper | Focus of the paper is on modern TLS fingerprinting. | No |
| JA4 independently computable | NOT_VERIFIED | MODERATE | Secondary Literature | Peer-Reviewed Paper | Authors report successful JA4 extraction, but independent replication notes coverage discrepancies using standard tools. | **YES (Critical P0)** |
| Bidirectional traffic present | NOT_VERIFIED | UNKNOWN | N/A | N/A | Assumed from standard PCAP capture, but not explicitly verified in public subset. | Yes |

---

## DS-007: Annotated Encrypted Network Traffic Dataset (Brno University)

| Claim | Status | Evidence Strength | Evidence Source | Source Type | Notes | Requires Empirical Verification |
|-------|--------|-------------------|-----------------|-------------|-------|---------------------------------|
| Contains modern SOHO/Malware traffic | VERIFIED_YES | STRONG | Zenodo Record / Dataset Paper | Official Repository | Documented capture of 2024 SOHO environment and 2025 sandboxed malware. | No |
| Raw PCAPs are available | VERIFIED_YES (RESTRICTED) | STRONG | Zenodo Record | Official Repository | Public downloads are Parquet files. PCAPs explicitly stated to be available "upon justified request". | Yes (Access required) |
| Modern TLS 1.3 present | NOT_VERIFIED | WEAK | Collection Date (2024-2025) | Inference | Highly likely given the collection date, but not explicitly confirmed in metadata without Parquet parsing. | Yes |
| JA4 independently computable | NOT_VERIFIED | UNKNOWN | N/A | N/A | Impossible to verify without PCAP access. | **YES (Critical P0)** |
| Flow features available | VERIFIED_YES | STRONG | Zenodo Record | Official Repository | Preprocessed Parquet files contain flow-level statistics. | No |

---

## DS-008: Malware-Traffic-Analysis.net (MTA)

| Claim | Status | Evidence Strength | Evidence Source | Source Type | Notes | Requires Empirical Verification |
|-------|--------|-------------------|-----------------|-------------|-------|---------------------------------|
| Contains real malware PCAPs | VERIFIED_YES | STRONG | malware-traffic-analysis.net | Official Repository | Continuous publication of malware threat hunting exercises. | No |
| Modern TLS 1.3 present | VERIFIED_YES | STRONG | MTA Exercise Descriptions | Official Documentation | Recent (2024-2026) exercises explicitly mention modern TLS/HTTPS C2. | No |
| JA4 independently computable | NOT_VERIFIED | UNKNOWN | N/A | N/A | PCAPs are available, but extraction success rate on these specific malware families is untested. | **YES (Critical P0)** |
| Benign traffic present | VERIFIED_NO | STRONG | MTA Scope | Official Documentation | Strictly malware and threat hunting traffic; lacks paired benign baseline. | No |
| Bidirectional traffic present | NOT_VERIFIED | UNKNOWN | N/A | N/A | Malware may abort handshakes early; bidirectionality needs verification per PCAP. | Yes |

---

## DS-009: Stratosphere Malware Capture Facility Project (MCFP)

| Claim | Status | Evidence Strength | Evidence Source | Source Type | Notes | Requires Empirical Verification |
|-------|--------|-------------------|-----------------|-------------|-------|---------------------------------|
| Contains real malware PCAPs | VERIFIED_YES | STRONG | Stratosphere IPS Datasets | Official Repository | Long-running academic malware capture project. | No |
| Modern TLS 1.3 present | NOT_VERIFIED | WEAK | Metadata | Informal Description | Varies heavily by malware family; many rely on older TLS versions. Needs curation. | Yes |
| JA4 independently computable | NOT_VERIFIED | UNKNOWN | N/A | N/A | Unknown until specific modern TLS captures are filtered and tested. | **YES (Critical P0)** |
| Benign traffic present | VERIFIED_NO | STRONG | Stratosphere Scope | Official Documentation | MCFP focuses on malicious captures. | No |
| Labels are reliable | NOT_VERIFIED | MODERATE | Documentation | Official Documentation | Sandbox artifacts are prevalent; labels identify the binary executed, not always the specific flow intent. | Yes |

---

## DS-010: IoT-23 (Aposemat)

| Claim | Status | Evidence Strength | Evidence Source | Source Type | Notes | Requires Empirical Verification |
|-------|--------|-------------------|-----------------|-------------|-------|---------------------------------|
| Contains malware/botnet PCAPs | VERIFIED_YES | STRONG | Zenodo Record / Original Paper | Official Repository | 20 malware captures and 3 benign captures. | No |
| Modern TLS 1.3 present | VERIFIED_NO | STRONG | Collection Date (2018-2019) | Official Documentation | Collection pre-dates widespread TLS 1.3 adoption; highly IoT focused (often unencrypted or legacy TLS). | No |
| JA4 independently computable | NOT_VERIFIED | UNKNOWN | N/A | N/A | Older TLS/SSL versions may lack required extensions for JA4. | Yes |
| Flow features available | VERIFIED_YES | STRONG | Zenodo Record | Official Repository | Zeek `conn.log` files provided. | No |
| Appropriate for Enterprise C2 | VERIFIED_NO | STRONG | Original Paper | Peer-Reviewed Paper | Traffic behavior is strictly IoT (Mirai, Torii, etc.), differing fundamentally from endpoint malware. | No |
