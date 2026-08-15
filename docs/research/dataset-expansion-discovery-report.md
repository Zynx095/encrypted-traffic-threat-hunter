# ETTH Dataset Expansion Discovery Report

## 1. Executive Summary
Phase 5 Step 11 was initiated because existing registered datasets (DS-001 through DS-005) failed to provide a fully verified primary malware dataset capable of supporting the JA4+Flow core experiment. This report documents an exhaustive candidate-discovery search targeting modern encrypted malware/C2 datasets. We investigated five user-specified high-priority targets and discovered several viable candidates. While no "perfect" public dataset exists that trivially fulfills all requirements without academic request or manual curation, four highly credible candidates have been identified for Phase 6 empirical verification.

## 2. Search Methodology
The search strategy prioritized recent publications (2024–2026) focusing on TLS fingerprinting (JA4, JA3), encrypted Command-and-Control (C2), and modern TLS 1.3 traffic. 

## 3. Search Sources
- Zenodo
- GitHub (academic repositories)
- Academic databases (IEEE Xplore, arXiv)
- Stratosphere IPS / CTU resources
- Malware-Traffic-Analysis.net

## 4. Inclusion Criteria
- Raw PCAP availability (mandatory for JA4 extraction)
- Evidence of malicious traffic (malware/C2)
- Potential modern TLS (1.2+) representation
- Potential bidirectional flows
- Academic/research provenance or high industry credibility

## 5. Exclusion Criteria
- Datasets distributed *only* as CSV/TSV flow features
- Datasets consisting *only* of unencrypted traffic
- Datasets explicitly utilizing outdated protocols exclusively (e.g., SSL 3.0)

## 6. Candidate Dataset Table
| ID | Dataset | Source | PCAP | Malware | TLS 1.3 | JA4 Status | Suitability |
|----|---------|--------|------|---------|---------|------------|-------------|
| DS-006 | Beyond JA4+ Dataset | Brno Univ. | YES (Subset) | YES | YES | PENDING | HIGH |
| DS-007 | Annotated Encrypted Traffic | Brno Univ. | YES (Req) | YES | PENDING | PENDING | HIGH |
| DS-008 | Malware-Traffic-Analysis.net | MTA | YES | YES | YES | PENDING | MEDIUM |
| DS-009 | Stratosphere MCFP | CTU | YES | YES | PENDING | PENDING | MEDIUM |
| DS-010 | IoT-23 (Aposemat) | Stratosphere | YES | YES | NO | PENDING | LOW |

## 7. Detailed Evaluation of High-Priority Candidates

### TQH-C2 ("An Encrypted Command-and-Control Traffic Dataset Across Protocols and Encryption Layers")
- **Source:** Zenodo (Reported 2026)
- **Evaluation:** Extensive searches across Zenodo, IEEE, arXiv, and GitHub failed to locate a public dataset matching this title or acronym. It is likely embargoed, published under a different name, or an internal project identifier.
- **Status:** **REJECTED (Not Found)**

### DS-006: Beyond JA4+ / Matoušek Dataset
- **Source:** Brno University of Technology / NES Research (`matousp/tls-fingerprinting`, `matousp/malware-analysis`)
- **Evaluation:** Directly addresses JA4+ fingerprinting for malware detection. Contains authenticated network traces of benign apps and various malware families.
- **Limitations:** Public GitHub repositories typically host only a subset of PCAPs due to size constraints. Full PCAPs require contacting Petr Matoušek. Literature notes extraction coverage discrepancies between NFStream and official JA4 tools.
- **Status:** **PENDING VERIFICATION (Primary Candidate)**

### DS-007: Annotated Encrypted Network Traffic Dataset
- **Source:** Ondřej Ryšavý / Brno University of Technology (Zenodo)
- **Evaluation:** Contains modern SOHO benign traffic and sandboxed malware. Highly relevant to current encrypted traffic research.
- **Limitations:** Raw PCAPs are restricted and require a justified academic request. Public downloads are preprocessed Apache Parquet files, which cannot be used for independent JA4 extraction.
- **Status:** **PENDING VERIFICATION (Primary Candidate)**

### DS-008: Malware-Traffic-Analysis.net (MTA)
- **Source:** Brad Duncan / MTA
- **Evaluation:** The premier source for real-world malware PCAPs. Continuously updated (2024-2026). Known to contain TLS 1.3 C2 traffic.
- **Limitations:** Primarily curated for threat hunting exercises, not machine learning. Requires intensive manual curation to filter and organize by malware family. Must be combined with a separate benign dataset (introducing severe leakage risks).
- **Status:** **PENDING VERIFICATION (Secondary Malware / Cross-Dataset Generalization)**

### DS-009: Stratosphere Malware Capture Facility Project (MCFP)
- **Source:** Stratosphere IPS / CTU
- **Evaluation:** Provides continuous, modern malware PCAPs captured in controlled environments. Superior to the obsolete CTU-13.
- **Limitations:** Sandbox artifacts are highly prevalent. TLS versions vary heavily by malware family. Requires manual curation and dataset blending.
- **Status:** **PENDING VERIFICATION (Secondary Malware)**

## 8. Newly Discovered Candidates
- **DS-010: IoT-23 (Aposemat):** Hosted on Zenodo. Contains large volumes of malicious botnet traffic. However, IoT traffic behaves fundamentally differently from general endpoint/enterprise traffic, making it less suitable as the *primary* dataset for a generalized threat hunter.

## 9. Dataset Capability Comparison
*(Note: See the updated `dataset-registry.csv` for the full 38-column comparison).*
The Brno University datasets (DS-006, DS-007) are the most scientifically rigorous candidates for the primary role because they provide paired benign and malicious traffic from a controlled academic environment. The MTA and MCFP datasets are highly realistic but require risky cross-dataset blending.

## 10. Leakage Risks
For DS-008 and DS-009, combining them with an external benign dataset (like CipherSpectrum) introduces **extreme dataset-source leakage risks**. 
- The model will easily learn the sandbox IP subnets, MAC addresses, and timing artifacts of the malware capture environment rather than the behavioral features of the encrypted flows.
- **Mitigation:** Strict normalization (masking IPs, MACs, Ports, and SNI strings) must be enforced.

## 11. Access/License Considerations
- **DS-006 & DS-007 (Brno Univ.):** Require explicit academic requests for full PCAP access.
- **DS-008 & DS-009 (MTA / MCFP):** Publicly available, but caution required when handling live malware PCAPs.

## 12. Candidates Requiring Academic Requests
1. Beyond JA4+ Dataset (Petr Matoušek, Brno Univ.)
2. Annotated Encrypted Network Traffic Dataset (Ondřej Ryšavý, Brno Univ.)

## 13. Top Candidates for Empirical Verification
1. **DS-006 (Beyond JA4+ Dataset)**
2. **DS-007 (Annotated Encrypted Network Traffic Dataset)**
3. **DS-008 (Malware-Traffic-Analysis.net)**

## 14. Rejected Candidates
- **TQH-C2:** Rejected (Could not be located).
- **Encrypted VPN Dataset (Zenodo 7301756):** Rejected (Lacks specific malware focus).

## 15. Recommended Verification Queue Updates
- [PENDING] Request academic access to DS-006 PCAPs.
- [PENDING] Request academic access to DS-007 PCAPs.
- [PENDING] Download a sample of 2024-2025 TLS 1.3 malware PCAPs from DS-008 (MTA) and verify JA4 computability.

## 16. Remaining Unknowns
- It is `NOT_VERIFIED` whether the Brno University datasets contain sufficient TLS 1.3 malware traffic (vs TLS 1.2).
- It is `NOT_VERIFIED` whether the MTA PCAPs provide sufficient bidirectional flow lengths for rigorous statistical features, given that many malware payloads abort quickly.

## 17. Step 12 Recommendation
Step 12 must focus on executing the verification queue tasks for DS-006, DS-007, and DS-008. Academic access requests should be drafted immediately. If access is granted, sample PCAPs must be evaluated exactly as CipherSpectrum was evaluated.

---
### Final Discovery Metrics
- **Candidates Discovered:** 7 investigated, 5 formalized.
- **Highest-Priority Candidates:** 1) DS-006, 2) DS-007, 3) DS-008.
- **Candidates potentially capable of JA4 + Flow + Malware:** DS-006, DS-007, DS-008, DS-009.
- **Candidates requiring academic access:** DS-006, DS-007.
- **Candidates requiring empirical PCAP verification:** DS-006, DS-007, DS-008, DS-009.
- **Phase Status:** Phase 5 Step 11 COMPLETE.
