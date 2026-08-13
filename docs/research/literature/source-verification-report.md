# Source Verification Report

**Date:** 2026-08-14  
**Phase:** Literature Review Phase 2 — Source Verification and Evidence Extraction  
**Project:** Encrypted Traffic Threat Hunter (ETTH)

---

## Summary

| Metric | Count |
|--------|-------|
| Total sources discovered | 28 |
| Total successfully verified | 28 |
| Total excluded | 0 |
| Foundational sources | 8 |
| Supporting sources | 18 |
| Background sources | 2 |
| Sources that could not be independently verified | 0 |
| Duplicate sources | 0 |

---

## Verified Sources by Quality

### FOUNDATIONAL (8)
Directly contributes to the theoretical or methodological foundation of ETTH.

| # | Citation Key | Title | Area |
|---|-------------|-------|------|
| 1 | anderson2016deciphering | Deciphering Malware's use of TLS (without Decryption) | Area 1 |
| 2 | althouse2017ja3 | Open Sourcing JA3 | Area 2 |
| 3 | althouse2019ja3s | TLS Fingerprinting with JA3 and JA3S | Area 2 |
| 4 | althouse2023ja4 | JA4+ Network Fingerprinting | Area 2 |
| 5 | rfc9849 | TLS Encrypted Client Hello (ECH) | Area 2 |
| 6 | wickramasinghe2025sok | SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers | Area 4 |
| 7 | akbari2022traffic | Traffic Classification in an Increasingly Encrypted Web | Area 1 |
| 8 | fu2024hypervision | Flow Interaction Graph Analysis: Unknown Encrypted Malicious Traffic Detection | Area 3 |

### SUPPORTING (18)
Useful evidence for specific components of ETTH but not central to the research question.

| # | Citation Key | Title | Area |
|---|-------------|-------|------|
| 1 | oh2021survey | A Survey on TLS-Encrypted Malware Network Traffic Analysis Applicable to Security Operations Centers | Area 1 |
| 2 | papadogiannaki2021survey | A survey on encrypted network traffic analysis applications, techniques, and countermeasures | Area 1 |
| 3 | matousek2025towards | Towards identification of network applications in encrypted traffic | Area 1 |
| 4 | barut2020tls | TLS Encrypted Application Classification Using Machine Learning with Flow Feature Engineering | Area 1 |
| 5 | matousek2021reliability | On Reliability of JA3 Hashes for Fingerprinting Mobile Applications | Area 2 |
| 6 | anderson2020accurate | Accurate TLS Fingerprinting using Destination Context and Approximate Matching | Area 2 |
| 7 | cisco2025ech | Encrypted Client Hello (ECH) Defense Strategies | Area 2 |
| 8 | ramos2023cobalt | Detecting Stealthy Cobalt Strike C&C Activities via Multi-Flow based Machine Learning | Area 3 |
| 9 | martinramos2022cobalt | A Machine Learning Based Approach to Detect Stealthy Cobalt Strike C&C Traffic | Area 3 |
| 10 | zhang2025beacon | Beaconing Detection in Encrypted Traffic: A SCADA-Based Hybrid Approach Using Zeek Metadata and Isolation Forest | Area 3 |
| 11 | akem2024realtime | Real-Time Encrypted Traffic Classification in Programmable Networks with P4 and Machine Learning | Area 3 |
| 12 | garcia2018efficient | Efficient Distribution-Derived Features for High-Speed Encrypted Flow Classification | Area 3 |
| 13 | malekghaini2022data | Data Drift in DL: Lessons Learned From Encrypted Traffic Classification | Area 4 |
| 14 | singh2025interpretable | Interpretable Anomaly Detection in Encrypted Traffic | Area 4 |
| 15 | grabowski2025explainable | Explainable AI for Forensic Analysis: A Comparative Study of SHAP and LIME in Intrusion Detection Models | Area 4 |
| 16 | ugurlu2021classification | A new classification method for encrypted internet traffic using machine learning | Area 4 |
| 17 | zhang2022deepforest | Deep-Forest-Based Encrypted Malicious Traffic Detection | Area 4 |
| 18 | zhao2025sugar | The Sweet Danger of Sugar: Debunking Representation Learning for Encrypted Traffic Classification | Area 5 |

### BACKGROUND (2)
Provides context but does not directly support the proposed methodology.

| # | Citation Key | Title | Area |
|---|-------------|-------|------|
| 1 | oh2021survey | A Survey on TLS-Encrypted Malware Network Traffic Analysis Applicable to Security Operations Centers | Area 1 |
| 2 | papadogiannaki2021survey | A survey on encrypted network traffic analysis applications, techniques, and countermeasures | Area 1 |

### EXCLUDE (0)
None.

---

## Detailed Verification Table

| Source | Verified | Type | Quality | Area | ETTH Relevance |
|--------|----------|------|---------|------|----------------|
| akbari2022traffic | Yes | Peer-Reviewed Paper | FOUNDATIONAL | Area 1 | High - protocol-agnostic feature engineering |
| oh2021survey | Yes | Peer-Reviewed Survey | BACKGROUND | Area 1 | High - comprehensive TLS-encrypted NTA survey |
| papadogiannaki2021survey | Yes | Peer-Reviewed Survey | BACKGROUND | Area 1 | High - broad encrypted traffic analysis survey |
| matousek2025towards | Yes | Peer-Reviewed Paper | SUPPORTING | Area 1 | High - JA3/JA4 comparison with annotated dataset |
| anderson2016deciphering | Yes | Peer-Reviewed Paper | FOUNDATIONAL | Area 1 | Very High - seminal malware TLS detection work |
| barut2020tls | Yes | Peer-Reviewed Paper | SUPPORTING | Area 1 | High - flow feature engineering for TLS |
| althouse2017ja3 | Yes | Technical Documentation | FOUNDATIONAL | Area 2 | Very High - original JA3 specification |
| althouse2019ja3s | Yes | Technical Documentation | FOUNDATIONAL | Area 2 | Very High - JA3S extension |
| matousek2021reliability | Yes | Peer-Reviewed Paper | SUPPORTING | Area 2 | High - JA3 collision/stability evidence |
| althouse2023ja4 | Yes | Technical Documentation | FOUNDATIONAL | Area 2 | Very High - JA4 specification |
| anderson2020accurate | Yes | arXiv Preprint | SUPPORTING | Area 2 | High - destination-aware TLS fingerprinting |
| rfc9849 | Yes | Standards Document | FOUNDATIONAL | Area 2 | Very High - ECH standard impacting visibility |
| cisco2025ech | Yes | Technical Documentation | SUPPORTING | Area 2 | High - ECH operational impact |
| fu2024hypervision | Yes | Peer-Reviewed Paper | FOUNDATIONAL | Area 3 | Very High - unsupervised flow interaction detection |
| ramos2023cobalt | Yes | Peer-Reviewed Paper | SUPPORTING | Area 3 | High - multi-flow Cobalt Strike detection |
| martinramos2022cobalt | Yes | Peer-Reviewed Paper | SUPPORTING | Area 3 | High - single-flow Cobalt Strike baseline |
| zhang2025beacon | Yes | Peer-Reviewed Paper | SUPPORTING | Area 3 | High - Zeek metadata beacon detection |
| akem2024realtime | Yes | Peer-Reviewed Paper | SUPPORTING | Area 3 | High - in-switch RF for encrypted traffic |
| garcia2018efficient | Yes | Peer-Reviewed Paper | SUPPORTING | Area 3 | High - distribution-derived flow features |
| wickramasinghe2025sok | Yes | Peer-Reviewed Paper | FOUNDATIONAL | Area 4 | Very High - NTC pitfalls and evaluation rigor |
| malekghaini2022data | Yes | Peer-Reviewed Paper | SUPPORTING | Area 4 | High - data drift in DL encrypted traffic |
| singh2025interpretable | Yes | arXiv Preprint | SUPPORTING | Area 4 | High - XGBoost + SHAP for encrypted traffic |
| grabowski2025explainable | Yes | Peer-Reviewed Paper | SUPPORTING | Area 4 | High - SHAP/LIME comparison for IDS |
| ugurlu2021classification | Yes | Peer-Reviewed Paper | SUPPORTING | Area 4 | High - XGBoost for encrypted traffic |
| zhang2022deepforest | Yes | Peer-Reviewed Paper | SUPPORTING | Area 4 | High - deep forest for small-scale encrypted data |
| zhao2025sugar | Yes | arXiv Preprint | SUPPORTING | Area 5 | High - representation learning pitfalls |
| wang2025bias | Yes | arXiv Preprint | SUPPORTING | Area 5 | High - shortcut learning in NTC |
| malekghaini2025drift | Yes | arXiv Preprint | SUPPORTING | Area 5 | High - dataset stability benchmarking |

---

## Duplicate Sources

None identified. All 28 sources are distinct works.

---

## Sources That Could Not Be Independently Verified

None. All 28 sources have traceable URLs or DOIs that resolve to the claimed content.

---

## Weak Areas in the Corpus

1. **Limited JA4 empirical validation.** Most JA4 material comes from official FoxIO documentation and one comparative study (Matousek et al. 2025). There is a shortage of independent academic evaluations of JA4 collision rates and stability across diverse application sets.

2. **Sparse adversarial-adaptation literature for flow-level detectors.** While adversarial evasion for flow-based C2 detection exists, there is limited research on how adversaries might specifically evade JA4 + flow-behavior fusion detectors.

3. **Few real-world SOC deployment studies.** Most evaluations use public datasets (ISCXVPN2016, CICIDS2017, CTU-13). There is a gap in peer-reviewed studies validating encrypted-traffic detectors in production SOC environments with live traffic.

4. **ECH impact is mostly operational, not academic.** RFC 9849 and Cisco documentation describe ECH well, but peer-reviewed measurements of ECH adoption rates and its quantitative impact on TLS-fingerprinting accuracy in the wild are still emerging.

5. **Explainability specifically for TLS-fingerprint-based scoring.** Existing XAI-IDS literature focuses on flow-feature-based models. There is limited work explaining decisions that hinge primarily on JA4/JA3 hashes combined with behavioral metadata.

---

## Important Evidence Gaps

1. **JA4 collision and stability under TLS 1.3/ECH:** No independent academic study measuring JA4 uniqueness and stability across diverse applications under modern TLS configurations.
2. **Fingerprint + behavior fusion:** No published study explicitly combining JA4/JA3S with flow-level behavioral features (beaconing, packet-size distributions, IAT patterns) in a unified explainable scoring system.
3. **Real-world false positive rates:** Most evaluations report accuracy on curated datasets; few provide false positive rates in live network environments with diverse benign traffic.
4. **Adversarial robustness:** Limited research on how adversaries might modify JA4-visible fields or flow behaviors to evade detection while maintaining functional C2 communications.
5. **Longitudinal evaluation:** Few studies evaluate classifier performance over extended time periods (months/years) to assess concept drift and maintenance requirements.

---

## Files Created or Modified

| File | Action | Description |
|------|--------|-------------|
| `docs/research/literature/literature-matrix.csv` | Created | 28-row matrix with structured evidence extraction |
| `docs/research/literature/annotated-bibliography/anderson2016deciphering.md` | Created | Annotation for foundational source |
| `docs/research/literature/annotated-bibliography/althouse2017ja3.md` | Created | Annotation for foundational source |
| `docs/research/literature/annotated-bibliography/althouse2019ja3s.md` | Created | Annotation for foundational source |
| `docs/research/literature/annotated-bibliography/althouse2023ja4.md` | Created | Annotation for foundational source |
| `docs/research/literature/annotated-bibliography/rfc9849.md` | Created | Annotation for foundational source |
| `docs/research/literature/annotated-bibliography/wickramasinghe2025sok.md` | Created | Annotation for foundational source |
| `docs/research/literature/annotated-bibliography/akbari2022traffic.md` | Created | Annotation for foundational source |
| `docs/research/literature/annotated-bibliography/fu2024hypervision.md` | Created | Annotation for foundational source |
| `docs/research/literature/corpus-manifest.csv` | Modified | Added verification_status, source_quality, evidence_availability columns |
| `docs/research/literature/corpus-discovery-notes.md` | Created (Phase 1) | Methodology and gap analysis |
| `docs/research/literature/README.md` | Modified (Phase 1) | Research-corpus status section |

---

## Next Steps

1. Review and refine source quality assignments (FOUNDATIONAL/SUPPORTING/BACKGROUND) with research team.
2. Read full texts of remaining SUPPORTING sources to extract additional evidence for the literature matrix.
3. Synthesize cross-paper observations in `synthesis-notes.md`.
4. Populate the five thematic section files (`section-01-*` through `section-05-*`).
5. Verify that the timeline gate (≥40 sources in the matrix) is met before narrative writing begins.
