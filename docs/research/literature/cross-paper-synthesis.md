# Cross-Paper Synthesis

## 1. Overview

The corpus contains 28 verified sources spanning peer-reviewed papers, preprints, technical documentation, and standards documents. The literature collectively studies encrypted traffic analysis from three complementary angles: (1) protocol-agnostic feature engineering and deep learning classification; (2) TLS-specific fingerprinting standards (JA3, JA4, JA3S) and the impact of ECH on visibility; and (3) flow-based behavioral detection of malicious patterns such as C2 beaconing. A smaller but critical subset examines machine learning evaluation rigor, concept drift, dataset bias, and explainability.

**What the literature collectively knows:**
- Useful signal survives TLS encryption in the form of flow statistics, packet-size distributions, inter-arrival times, and TLS handshake metadata.
- TLS fingerprinting (JA3/JA4) can identify client applications and server responses, but suffers from collisions, instability, and—under ECH—potential loss of SNI visibility.
- Supervised ML models achieve high reported accuracy on curated datasets, but recent systematization work reveals widespread overfitting, data leakage, and poor generalization.
- Unsupervised and graph-based approaches can detect unknown encrypted attacks without labeled data, but their computational overhead and integration with TLS-specific features remain underexplored.

**What remains insufficiently explored:**
- Independent academic validation of JA4 collision rates and stability across diverse application sets.
- Explicit fusion of JA4/JA3S with flow-level behavioral features in a unified explainable scoring system.
- Real-world SOC deployment studies with live traffic and reported false-positive rates.
- Quantitative peer-reviewed measurements of ECH adoption and its impact on existing detection pipelines.
- XAI methods specifically for decisions that combine TLS fingerprints with behavioral metadata.

---

## 2. Encrypted Traffic Analysis

### What is established (supported by multiple papers)

**A. Metadata-only analysis is feasible.**
Multiple sources confirm that packet-size distributions, inter-arrival times, flow durations, byte ratios, and TLS handshake metadata carry sufficient signal for classification without payload decryption [akbari2022traffic, oh2021survey, papadogiannaki2021survey, barut2020tls, garcia2018efficient]. The consensus spans surveys, peer-reviewed experiments, and operational documentation.

**B. Protocol-agnostic features improve generalization.**
Akbari et al. (2022) demonstrate that flow statistics combined with traffic shape (packet sizes, directions, IATs) and raw handshake bytes outperform state-of-the-art methods by nearly 50% fewer false classifications. The same architecture generalizes across HTTP/2 and QUIC by changing only the training data. This is supported by multiple surveys [oh2021survey, papadogiannaki2021survey] which emphasize the need for protocol-agnostic approaches as encryption evolves.

**C. TLS handshake metadata is a high-value feature source.**
Anderson & McGrew (2017) show that malware family attribution accuracy reaches 90.3% from a single encrypted flow using only observable TLS parameters. Matousek et al. (2025) confirm that JA4+JA4S achieves >90% accuracy for application identification. The TLS handshake exposes cipher suites, extensions, TLS version, and certificate attributes—all usable without decryption.

**D. Deployment without decryption is operationally viable.**
Surveys [oh2021survey, papadogiannaki2021survey] identify three main deployment models: TLS interception, inspection using cryptographic functions, and passive inspection without decryption. The third model—passive inspection—is increasingly recommended for privacy and cost reasons, and is the operational context for ETTH.

### What is uncertain

**A. Long-term stability of metadata-only features.**
While short-term accuracy is well-documented, only Malekghaini et al. (2022) systematically study concept drift for encrypted traffic DL models. The longevity of flow-statistic and handshake-based classifiers under protocol evolution (TLS 1.3, ECH, QUIC) is not fully quantified.

**B. Generalization across network environments.**
Most evaluations use public datasets or single-site captures. Rosetta (Xie et al., 2023) shows that existing DL models degrade by up to 53% accuracy when tested in different network environments due to TCP mechanism effects on packet-length sequences. This raises questions about how well features validated in one environment transfer to another.

**C. False positive rates in live networks.**
Reported accuracy figures dominate the literature. Few papers provide false positive rates in realistic, noisy, live-network conditions with diverse benign traffic. This is critical for SOC adoption.

---

## 3. TLS Fingerprinting

### Evolution chain

```
TLS metadata (handshake fields)
    ↓
JA3 (2017) — MD5 hash of ordered ClientHello fields
    ↓
JA3 limitations — extension ordering, collisions, MD5 obsolescence
    ↓
JA4 (2023) — human-readable, sorted hashes, GREASE-stripped, QUIC/DTLS support
    ↓
Remaining limitations — independent validation gap, ECH SNI loss, database maintenance
    ↓
ECH visibility challenge — SNI/ALPN encrypted, Outer ClientHello remains
```

### What is established about JA3 (supported by multiple papers)

**A. JA3 specification is stable and widely implemented.**
The original Salesforce blog post [althouse2017ja3] and follow-up [althouse2019ja3s] define JA3/JA3S clearly. JA3 extracts five fields from ClientHello (SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, Elliptic Curve Formats), concatenates them, and MD5-hashes the result. JA3S does the same for ServerHello with three fields.

**B. JA3 alone is insufficient for reliable identification.**
Multiple sources confirm JA3 limitations:
- Matousek et al. (2021) report collision rates and instability for mobile apps, concluding JA3 alone is insufficient.
- Matousek et al. (2025) show JA3 performs poorly due to random extension ordering creating multiple fingerprints per application.
- Anderson & McGrew (2020) demonstrate that hundreds of processes can map to the same JA3 string, and that 59 of 67 malware JA3 hashes from abuse.ch were also used by benign software.
- The JA4 blog post [althouse2023ja4] explicitly positions JA4 as a replacement for JA3 due to these limitations.

**C. JA3+JA3S reduces false positives compared to JA3 alone.**
Althouse & Lindeman (2019) show that combined client-server fingerprinting creates a more accurate identification of the cryptographic negotiation. Reverse-engineering of abuse.ch feeds found 55 of 64 malware JA3 hashes were also used by benign software, highlighting the false positive problem.

### What is established about JA4 (supported by fewer sources)

**A. JA4 specification is authoritative but not yet widely academically validated.**
The FoxIO blog [althouse2023ja4] and GitHub repository provide the definitive JA4 specification. JA4 sorts cipher and extension lists before hashing, strips GREASE values, uses truncated SHA-256 instead of MD5, and produces human-readable fingerprints. It supports TLS over TCP, QUIC, and DTLS.

**B. JA4+JA4S shows promise in limited comparative studies.**
Matousek et al. (2025) report that JA4+JA4S achieves >90% accuracy for application identification, outperforming JA3+JA3S. However, this is one comparative study with a specific application set. Independent academic validation across diverse environments is limited.

**C. JA4's advantages over JA3 are design-level, not yet proven at scale.**
The sorting behavior should mitigate extension-ordering randomization. The human-readable format aids analyst understanding. However, empirical collision rates, stability under TLS 1.3, and performance under ECH have not been independently measured in peer-reviewed literature.

### Areas of uncertainty

**A. JA4 empirical validation.**
Only one peer-reviewed comparative study [matousek2025towards] directly compares JA3 and JA4. The corpus lacks independent large-scale measurements of JA4 uniqueness, collision rates, and longitudinal stability.

**B. JA4 under ECH.**
ECH encrypts SNI and ALPN, which are captured in JA4's header fields. The operational Cisco documentation [cisco2025ech] suggests Outer ClientHello fields remain visible, but the impact on JA4 fingerprint quality is not quantified.

**C. Destination context for JA4.**
Anderson & McGrew (2020) showed that adding destination context dramatically improves JA3-based identification. Whether similar gains apply to JA4, and how to implement this without SNI under ECH, is unexplored.

---

## 4. Flow-Based Behavioral Analysis

### Common feature families (supported by multiple papers)

| Feature Family | Papers Supporting | Notes |
|----------------|-------------------|-------|
| Packet size statistics (mean, std, min, max) | garcia2018efficient, akem2024realtime, akbari2022traffic, ramsos2023cobalt, martinramos2022cobalt | Universally used; unaffected by encryption |
| Inter-arrival times (IATs) | garcia2018efficient, akem2024realtime, akbari2022traffic, zhang2025beacon | Key for beaconing detection |
| Flow duration | martinramos2022cobalt, ramos2023cobalt, barut2020tls | Used but noted as variable due to network latency |
| Byte counts (orig/resp) | martinramos2022cobalt, ramos2023cobalt, martinramos2022cobalt | Distinguishes upload/download patterns |
| Packet counts | martinramos2022cobalt, ramos2023cobalt | Simple but effective |
| Connection state/history | martinramos2022cobalt | Zeek-specific; captures transaction patterns |
| TLS session grouping | ramos2023cobalt, akbari2022traffic | Multi-flow features derived from TLS session groups |
| Distribution-derived features (histograms, KSD bins) | garcia2018efficient | Outperforms simple statistical moments |
| Coefficient of Variation (CV) of intervals | zhang2025beacon, ramos2023cobalt | Identifies low-jitter periodic flows |
| Multi-flow temporal features (dur_mean, dur_std, int_mean, int_std) | ramos2023cobalt | Captures cross-session behavioral patterns |

### Common detection targets

- **C2 beaconing:** Low-jitter periodic flows detectable via CV thresholds or Isolation Forest [zhang2025beacon, ramos2023cobalt, martinramos2022cobalt].
- **Unknown encrypted malicious traffic:** Flow interaction graph patterns reveal attacks even when individual flows resemble benign traffic [fu2024hypervision].
- **Application classification:** Flow statistics plus handshake features distinguish audio, email, chat, video, and streaming [barut2020tls, matousek2025towards].
- **Malware family attribution:** Distinct TLS parameter usage enables family-level identification [anderson2016deciphering].

### Known limitations

**A. Features vulnerable to adversarial modification.**
Martin Ramos et al. (2022) note that proxy-based adversarial attacks can modify flow features (duration, byte counts, packet counts) to evade detection while preserving malware functionality.

**B. Features affected by network conditions.**
Xie et al. (2023) show that TCP mechanisms (retransmission, reordering, congestion control) dramatically change packet-length sequences across network environments, causing up to 53% accuracy degradation for DL models.

**C. Class imbalance in public datasets.**
Barut et al. (2020) use SMOTE augmentation for class imbalance. The Wickramasinghe SoK (2025) notes that ISCXVPN2016 and other public datasets exhibit significant class imbalance detrimental to deep learning performance.

**D. Temporal behavior requires sufficient history.**
Beaconing detection requires dozens of connections to establish a rhythm [zhang2025beacon, ramos2023cobalt]. Low-event or high-jitter flows remain difficult to classify with limited flow history.

---

## 5. Machine Learning

### Commonly used models

| Model | Papers Using | Context |
|-------|-------------|---------|
| Random Forest | martinramos2022cobalt, garcia2018efficient, akem2024realtime, zhang2022deepforest, ugurlu2021classification | Widely used baseline; good for tabular flow features |
| XGBoost | ugurlu2021classification, zhang2022deepforest, singh2025interpretable, malekghaini2025drift | Often achieves highest accuracy on flow-feature datasets |
| Neural Network (MLP) | martinramos2022cobalt | Poor detection rate (3%) in single-flow Cobalt Strike study |
| CNN / LSTM | akbari2022traffic, malekghaini2022data | Used for time-series and raw-byte classification |
| Deep Forest (CaForest) | zhang2022deepforest | Performs well on small-scale unbalanced data |
| Isolation Forest | zhang2025beacon, singh2025interpretable | Unsupervised anomaly detection; no labels required |
| K-Means | martinramos2022cobalt | Unsupervised baseline; poor performance for C2 detection |
| Graph Learning (unsupervised) | fu2024hypervision | Detects unknown attacks without labeled data |

### What the evidence shows about model performance

**A. Tree-based models dominate flow-feature-based classification.**
Random Forest and XGBoost are the most frequently used models for tabular flow features. Ugurlu et al. (2021) report XGBoost at 94.53% accuracy on ISCX VPN-nonVPN. Zhang et al. (2022) report 94.9% accuracy with deep forest on SSL/TLS malicious traffic. However, these results come from specific datasets and may not transfer.

**B. Deep learning models show high reported accuracy but suffer from evaluation flaws.**
Akbari et al. (2022) report >95% accuracy with CNN/LSTM. However, the Wickramasinghe SoK (2025) reveals that many such results rely on legacy datasets, SNI data leakage, and per-packet split shortcuts. When evaluated with proper methodology (frozen encoders, per-flow splits), representation learning models often perform poorly.

**C. Model superiority is context-dependent.**
No single model is shown to dominate across all datasets and tasks. XGBoost excels on some flow-feature tasks [ugurlu2021classification, singh2025interpretable]; neural networks excel on multi-flow Cobalt Strike detection [ramos2023cobalt]; deep forest excels on small-scale unbalanced data [zhang2022deepforest]; unsupervised graph learning excels at unknown attack detection [fu2024hypervision].

### Explainability methods

**A. SHAP is preferred for global and forensic explanations.**
Singh et al. (2025) and Grabowski & Xu (2025) demonstrate SHAP's effectiveness for encrypted traffic anomaly detection and IDS forensics. SHAP provides consistent, game-theoretic feature attributions suitable for validation and auditing.

**B. LIME complements SHAP for local incident-response explanations.**
Grabowski & Xu (2025) find LIME useful for rapid local explanations during incident response, while SHAP is superior for forensic reporting and regulatory compliance.

**C. Explainability for TLS-fingerprint-based decisions is underexplored.**
Existing XAI-IDS work focuses on flow-feature-based models. No source in the corpus addresses explainability for decisions that primarily hinge on JA4/JA3 hashes combined with behavioral metadata.

### Class imbalance

**A. SMOTE augmentation is used but not extensively studied.**
Barut et al. (2020) apply SMOTE for class imbalance in TLS application classification. The Wickramasinghe SoK (2025) notes that public datasets like ISCXVPN2016 have significant class imbalance that harms deep learning performance.

### Generalization and drift

**A. Cross-dataset generalization is poor.**
Malekghaini et al. (2022) show that DL models trained on old data degrade when tested on new data. Traffic-shape models are more resilient than TLS-header models. Rosetta (Xie et al., 2023) demonstrates up to 53% accuracy drop when models are tested in different network environments.

**B. Concept drift is acknowledged but not systematically measured.**
Malekghaini et al. (2022) propose architectural adaptations but note that automatic drift detection and adaptation remain open problems. Malekghaini et al. (2025) propose MFWDD for drift detection, but automatic optimization is not implemented.

---

## 6. Major Agreements Across Studies

1. **Metadata-only encrypted traffic analysis is feasible.** Supported by: akbari2022traffic, oh2021survey, papadogiannaki2021survey, barut2020tls, anderson2016deciphering, garcia2018efficient, akem2024realtime.

2. **Flow statistics and packet-size/IAT features retain discriminative power under encryption.** Supported by: garcia2018efficient, akem2024realtime, akbari2022traffic, barut2020tls, martinramos2022cobalt, ramos2023cobalt.

3. **Malware TLS behavior differs from benign traffic.** Supported by: anderson2016deciphering, oh2021survey.

4. **JA3 alone is insufficient for reliable identification due to collisions and instability.** Supported by: althouse2019ja3s, matousek2021reliability, matousek2025towards, anderson2020accurate.

5. **JA3+JA3S (or JA4+JA4S) reduces false positives compared to single-side fingerprinting.** Supported by: althouse2019ja3s, matousek2025towards.

6. **ECH encrypts SNI and ALPN, reducing traditional visibility.** Supported by: rfc9849, cisco2025ech.

7. **Public datasets contain legacy issues (unencrypted traffic, deprecated ciphers, class imbalance).** Supported by: wickramasinghe2025sok, zhao2025sugar, wang2025bias.

8. **Per-packet data splitting and SNI leakage cause overfitting in DL classifiers.** Supported by: wickramasinghe2025sok, zhao2025sugar.

9. **Unsupervised/graph-based methods can detect unknown encrypted attacks without labeled data.** Supported by: fu2024hypervision.

10. **Explainability (SHAP/LIME) is needed for analyst trust and forensic compliance.** Supported by: singh2025interpretable, grabowski2025explainable.

---

## 7. Major Differences Across Studies

| Topic | Difference | Sources |
|-------|-----------|---------|
| JA3 vs JA4 performance | Matousek et al. (2025) report JA4+JA4S >90% vs JA3 poor; but independent validation is limited | matousek2025towards vs. limited independent studies |
| Best ML model | XGBoost reported best on some flow-feature tasks [ugurlu2021classification]; neural network best on multi-flow C2 [ramos2023cobalt]; deep forest best on small-scale data [zhang2022deepforest] | Multiple |
| Feature importance | Barut et al. (2020) find source port most important (questionable due to OS randomization); Akbari et al. (2022) emphasize traffic shape over raw bytes | barut2020tls vs. akbari2022traffic |
| Drift resilience | Malekghaini et al. (2022) find traffic-shape models more resilient than TLS-header models; Rosetta finds all DL models degrade significantly across environments | malekghaini2022data vs. Rosetta (not in corpus) |
| Representation learning value | Zhao et al. (2025) show representation learning fails with frozen encoders; some prior works claim high accuracy without such evaluation | zhao2025sugar vs. prior DL literature |
| ECH impact magnitude | Cisco (2025) reports low observed ECH adoption (33 matches at conference); RFC 9849 predicts significant future impact | cisco2025ech vs. rfc9849 |

---

## 8. Recurring Limitations

### Across multiple papers

1. **Dataset bias and legacy issues.** Public datasets contain unencrypted traffic, deprecated cipher suites (3DES, RC4), and class imbalance [wickramasinghe2025sok, zhao2025sugar, wang2025bias].

2. **Overfitting due to data leakage.** SNI exposure, per-packet splits, and session-specific artifacts inflate reported accuracy [wickramasinghe2025sok, zhao2025sugar].

3. **Concept drift and temporal degradation.** Model performance degrades when trained on old data and tested on new data [malekghaini2022data, malekghaini2025drift].

4. **Limited generalization across networks.** Models trained in one environment often fail in others [malekghaini2022data, Rosetta findings referenced in corpus].

5. **Sandbox bias in malware datasets.** Malware executed in sandboxes exhibits different TLS behavior than real-world malware [anderson2016deciphering, oh2021survey].

6. **False positive rates underreported.** Most papers report accuracy; few provide false positive rates in realistic live-network conditions.

7. **Computational cost of explainability.** SHAP and LIME computation overheads are noted but not solved for high-throughput networks [singh2025interpretable, grabowski2025explainable].

8. **Feature maintenance burden.** Fingerprint databases require regular updates as applications evolve [althouse2017ja3, althouse2019ja3s, matousek2025towards].

---

## 9. Potential Research Gaps

### Gap 1: Independent academic validation of JA4 collision rates and stability

- **Statement:** No peer-reviewed study independently measures JA4 uniqueness, collision rates, and longitudinal stability across diverse application sets and TLS versions.
- **Supporting sources:** matousek2025towards (one comparative study), althouse2023ja4 (specification only), matousek2021reliability (JA3 only).
- **Evidence strength:** HIGH (absence of evidence is clear from corpus coverage).
- **Why it matters to ETTH:** ETTH's core fingerprinting component relies on JA4. Unverified collision rates could undermine the entire approach.

### Gap 2: No published study combining JA4/JA3S with flow-level behavioral features in a unified explainable scoring system

- **Statement:** Existing work treats TLS fingerprinting and flow-based behavioral detection as separate threads. No source in the corpus proposes or evaluates a unified system that fuses JA4 fingerprints with multi-flow behavioral features (packet-size distributions, IAT patterns, beaconing scores) under a single explainable ML framework.
- **Supporting sources:** matousek2025towards (fingerprinting alone), ramos2023cobalt (behavioral features without JA4), singh2025interpretable (XAI without JA4), fu2024hypervision (graph-based without fingerprints).
- **Evidence strength:** HIGH (explicit absence across all sources).
- **Why it matters to ETTH:** This is ETTH's proposed contribution. The gap must be acknowledged and empirically addressed.

### Gap 3: Limited real-world SOC deployment studies with live traffic and reported false-positive rates

- **Statement:** Most evaluations use public datasets (ISCXVPN2016, CICIDS2017, CTU-13) or lab-generated traffic. Few provide false-positive rates in live enterprise networks with diverse benign applications.
- **Supporting sources:** martinramos2022cobalt (real-world attacks but lab features), zhang2025beacon (lab-generated SCADA traffic), cisco2025ech (operational observations, not academic study).
- **Evidence strength:** MEDIUM (some real-world validation exists but is sparse).
- **Why it matters to ETTH:** SOC adoption requires demonstrated false-positive rates in production environments.

### Gap 4: ECH impact is mostly operational, not quantitatively measured in peer-reviewed studies

- **Statement:** RFC 9849 and Cisco documentation describe ECH's visibility impact, but peer-reviewed measurements of ECH adoption rates and quantitative degradation of TLS-fingerprinting accuracy in the wild are not yet available.
- **Supporting sources:** rfc9849 (specification), cisco2025ech (operational, 33 matches observed), althouse2023ja4 (specification, mentions ECH).
- **Evidence strength:** HIGH (clear absence of peer-reviewed quantitative studies).
- **Why it matters to ETTH:** ECH could invalidate JA4's reliance on SNI and ALPN fields. ETTH needs to design ECH-resilient scoring.

### Gap 5: Limited XAI research for TLS-fingerprint-based decisions combined with behavioral metadata

- **Statement:** Existing XAI-IDS research explains flow-feature-based models (CICFlowMeter, NetFlow). No source addresses explainability for hybrid decisions that combine JA4/JA3 hashes with behavioral scoring.
- **Supporting sources:** grabowski2025explainable (XAI for flow features), singh2025interpretable (XAI for flow features), althouse2023ja4 (human-readable format but not ML explainability).
- **Evidence strength:** MEDIUM (XAI exists for related tasks but not this exact combination).
- **Why it matters to ETTH:** ETTH's explainable threat scoring must justify both fingerprint matches and behavioral anomalies to security analysts.

---

## 10. What Existing Research Does NOT Establish

The following conclusions **cannot** be made from the current corpus:

1. **Whether JA4 alone is sufficient for reliable encrypted traffic identification.** No independent study measures JA4 collision rates or stability at scale.

2. **Whether JA4 consistently outperforms JA3 across diverse environments.** Only one comparative study exists [matousek2025towards], with a limited application set. Cross-environment validation is absent.

3. **Whether combining JA4 with flow statistics produces better detection than either alone.** No published study explicitly evaluates this fusion in a controlled experiment.

4. **Whether a particular ML model is universally superior for encrypted traffic classification.** Model performance is context-dependent on dataset, feature set, and detection target.

5. **Whether ETTH's proposed methodology will work in production.** No source validates a system that combines JA4 fingerprinting, flow-level behavioral scoring, and explainable ML for SOC deployment.

6. **Whether ECH will significantly degrade JA4-based detection in the near term.** Cisco observed only 33 ECH matches at a conference; adoption trajectory is uncertain.

7. **Whether flow-level behavioral features can compensate for SNI loss under ECH.** No study quantifies this compensation effect.

8. **Whether explainable ML reduces false-positive rates in operational SOC settings.** XAI improves transparency but its impact on analyst decision-making and false-positive reduction is not measured.

---

## 11. Implications for ETTH

**What the literature suggests ETTH should investigate:**

1. **Protocol-agnostic feature engineering is well-justified.** The corpus strongly supports ETTH's focus on flow statistics, packet-size/IAT distributions, and TLS handshake metadata without payload decryption. The masking of SNI and canary features is also supported.

2. **JA4 is the most current fingerprinting standard, but its empirical limitations must be measured.** ETTH should not assume JA4 superiority without independent validation. Collision rates, stability under TLS 1.3, and performance under ECH should be quantified.

3. **Dual-fingerprint (JA4+JA4S) approach is supported but incomplete.** The literature shows client-server pairing reduces false positives, but ETTH must still address remaining ambiguities through behavioral scoring.

4. **Flow-level behavioral features (beaconing, IAT patterns, packet-size distributions) are validated detection signals.** Multiple papers confirm these features survive encryption and distinguish malicious from benign traffic.

5. **Unsupervised and graph-based detection paradigms deserve attention.** HyperVision's success at unknown encrypted attack detection suggests ETTH should consider anomaly-detection components beyond supervised classification.

6. **Explainability is necessary but not sufficient.** SHAP/LIME provide transparency, but their computational cost and forensic relevance must be evaluated in ETTH's specific context.

7. **Evaluation rigor is critical.** The Wickramasinghe SoK and Zhao et al.'s critique reveal that many published results are artifacts of flawed methodology. ETTH must adopt per-flow splits, SNI masking, frozen-encoder evaluation, and modern datasets to avoid similar pitfalls.

8. **Concept drift and dataset stability are operational realities.** ETTH should plan for model maintenance, drift detection, and periodic retraining from the outset.

**What ETTH must NOT yet claim:**
- JA4 superiority over JA3 (insufficient independent validation).
- Random Forest or XGBoost as the best model (context-dependent).
- Guaranteed detection of suspicious traffic (no method achieves this).
- ECH-resilient design (not yet quantitatively validated).

---

## Evidence Summary by Area

| Area | Sources | Key Finding | Confidence |
|------|---------|-------------|------------|
| Area 1 | akbari2022traffic, oh2021survey, papadogiannaki2021survey, matousek2025towards, anderson2016deciphering, barut2020tls | Metadata-only analysis is feasible; malware TLS behavior is distinguishable from benign traffic | HIGH |
| Area 2 | althouse2017ja3, althouse2019ja3s, althouse2023ja4, matousek2021reliability, matousek2025towards, anderson2020accurate, rfc9849, cisco2025ech | JA3 insufficient alone; JA4 improves format but lacks independent validation; ECH threatens SNI visibility | HIGH for JA3/ECH; MEDIUM for JA4 |
| Area 3 | fu2024hypervision, ramos2023cobalt, martinramos2022cobalt, zhang2025beacon, akem2024realtime, garcia2018efficient | Flow interaction patterns, packet-size/IAT features, and multi-flow behavioral features detect encrypted C2 and unknown attacks | HIGH |
| Area 4 | wickramasinghe2025sok, malekghaini2022data, singh2025interpretable, grabowski2025explainable, ugurlu2021classification, zhang2022deepforest | Tree-based models commonly used; DL suffers from evaluation flaws; SHAP/LIME for explainability; concept drift is real | HIGH for evaluation flaws; MEDIUM for model superiority |
| Area 5 | zhao2025sugar, wang2025bias, malekghaini2025drift | Representation learning pitfalls, shortcut learning, dataset bias, and drift detection are critical but not fully solved | HIGH for existence; MEDIUM for solutions |
