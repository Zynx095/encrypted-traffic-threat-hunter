# Corpus Discovery Notes

## Date
2026-08-14

## Phase
Literature Review Phase 1 — Research Corpus Discovery

---

## Search Methodology

Sources were identified through targeted web searches using the following queries and strategies:

1. **Academic database queries** — Searches for peer-reviewed papers on encrypted traffic analysis, TLS fingerprinting, flow-based intrusion detection, and ML for network security. Queries targeted ACM Digital Library, IEEE Xplore, arXiv, MDPI, and Springer.

2. **Technical documentation queries** — Direct searches for official JA4/FoxIO documentation, Salesforce JA3/JA3S blogs, IETF RFCs, and Cisco security documentation.

3. **Survey and SoK queries** — Searches for systemization-of-knowledge papers and recent surveys (2021–2025) to ensure coverage of contemporary issues such as TLS 1.3, ECH, dataset bias, and concept drift.

4. **Cross-reference snowballing** — Used reference lists within found surveys and papers to identify additional foundational and supporting sources.

No fabrications were used. Every source listed in `corpus-manifest.csv` has a traceable URL or DOI discovered during these searches.

---

## Source-Selection Criteria

### Inclusion Criteria
- **Peer-reviewed papers** from major security/networking venues (IEEE, ACM, IFIP, MDPI, Springer).
- **Major conference papers** (e.g., IEEE S&P, ACM CCS, IEEE INFOCOM, ACM SIGMETRICS, ICMLA).
- **arXiv preprints** when an important paper was not otherwise accessible or when the paper represents a very recent contribution (2024–2025).
- **Official technical documentation** for JA3/JA4 (Salesforce Engineering, FoxIO LLC).
- **Official standards documentation** (IETF RFC 9849 for ECH).
- **High-quality engineering/security research articles** from recognized vendors (Cisco, FoxIO) when they provide unique operational insight not found in academic literature.

### Exclusion Criteria
- Random blogs, SEO articles, Stack Overflow, generic tutorials.
- Sources with no identifiable authorship.
- Citation farms or predatory publishers.
- Duplicate papers (same work published in multiple venues without substantive differences).
- Papers requiring fabricated data or results to support ETTH claims.

---

## The Five Research Areas

### Area 1 — Encrypted Traffic Analysis
Focuses on the feasibility of classifying TLS-encrypted traffic without payload inspection. Key themes include flow metadata, TLS handshake features, SNI-based identification, and the comparison between fingerprinting and ML-based approaches. Sources were selected to establish the foundational motivation for ETTH: that useful signals survive encryption.

### Area 2 — TLS Fingerprinting (JA3 / JA4 / ECH)
Covers the evolution from JA3 to JA4, limitations of MD5 hashing, extension ordering instability, GREASE handling, and the impact of Encrypted Client Hello (ECH) on visibility. Includes official technical documentation, empirical reliability studies, and operational analyses of ECH deployment.

### Area 3 — Flow-Based Network Intrusion Detection
Addresses detection of malicious behavior using flow-level statistics, packet-size sequences, inter-arrival times, and beaconing/C2 detection. Sources span graph-based unsupervised detection (HyperVision), multi-flow ML for Cobalt Strike, beaconing detection with Zeek metadata, and in-switch programmable-dataplane classification.

### Area 4 — Machine Learning for Network Security
Covers supervised and deep learning models (Random Forest, XGBoost, deep forest, CNN/LSTM), explainability (SHAP, LIME), and operational challenges such as data drift and concept drift. Sources were chosen to inform ETTH's planned explainable ML pipeline and to highlight model selection considerations.

### Area 5 — Research Gaps
Focuses on limitations that ETTH must acknowledge or address: dataset bias, shortcut learning, concept drift, generalization across networks, ECH-induced visibility loss, and the fragility of representation-learning approaches. Sources are primarily critical analyses (SoK papers) and recent preprints that identify methodological pitfalls.

---

## Quality Judgment

Sources were evaluated against the following criteria:

- **Venue credibility:** Preference for peer-reviewed venues with rigorous review processes (IEEE, ACM, IFIP, MDPI, Springer).
- **Empirical validation:** Papers with real-world or public-dataset experiments were preferred over purely theoretical work.
- **Traceability:** All claims must link to a verifiable URL, DOI, or arXiv ID.
- **Recency:** Priority given to 2021–2025 sources to reflect TLS 1.3, ECH, and modern ML practices. Foundational papers (e.g., Anderson & McGrew 2016/2017, JA3 2017) were included because they established the field.
- **Avoidance of citation farms:** Excluded papers from unknown or low-credibility venues.

---

## Important Gaps in the Initial Corpus

1. **Limited coverage of JA4 empirical validation.** Most JA4 material comes from official FoxIO documentation and one comparative study (Matousek et al. 2025). There is a shortage of independent academic evaluations of JA4 collision rates and stability across diverse application sets.

2. **Sparse adversarial-adaptation literature for flow-level detectors.** While adversarial evasion for flow-based C2 detection exists (e.g., proxy-based evasion studies), there is limited research on how adversaries might specifically evade JA4 + flow-behavior fusion detectors.

3. **Few real-world SOC deployment studies.** Most evaluations use public datasets (ISCXVPN2016, CICIDS2017, CTU-13). There is a gap in peer-reviewed studies validating encrypted-traffic detectors in production SOC environments with live traffic.

4. **ECH impact is mostly operational, not academic.** RFC 9849 and Cisco documentation describe ECH well, but peer-reviewed measurements of ECH adoption rates and its quantitative impact on TLS-fingerprinting accuracy in the wild are still emerging.

5. **Explainability specifically for TLS-fingerprint-based scoring.** Existing XAI-IDS literature focuses on flow-feature-based models (CICFlowMeter, NetFlow). There is limited work explaining decisions that hinge primarily on JA4/JA3 hashes combined with behavioral metadata—the exact hybrid ETTH proposes.

---

## Files Updated

- `docs/research/literature/corpus-manifest.csv` — 28 candidate sources recorded.
- `docs/research/literature/README.md` — Research-corpus status section added.
- `docs/research/literature/corpus-discovery-notes.md` — This file.

---

## Next Steps

1. Read each included source and produce per-source annotations in `annotated-bibliography/`.
2. Populate `literature-matrix.csv` with structured extractions.
3. Synthesize findings in `synthesis-notes.md` and the five thematic section files.
4. Verify that the timeline gate (≥40 sources in the matrix) is met before narrative writing begins.
