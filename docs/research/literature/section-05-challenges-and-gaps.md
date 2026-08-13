# Section 5 — Challenges, Gaps, and Positioning of ETTH

## Objective

Synthesize limitations from Sections 1–4, articulate ETTH's specific contribution, and derive testable hypotheses for the experimental phase.

## Research Questions

- What recurring limitations and dataset biases weaken the evidence base?
- Which research gaps, if addressed, would most advance the state of the art?
- How can ETTH empirically validate JA4 + flow feature fusion under ECH conditions?

## Subsections

### 5.1 Synthesis of Limitations

The literature reveals limitations at three levels: technical (encryption and protocol evolution), machine-learning (dataset bias, overfitting, drift), and operational (deployment, explainability, analyst trust).

### 5.2 Dataset Bias and Reproducibility Failures

**Documented issues:**

1. **Legacy datasets contain unencrypted or weakly encrypted traffic.** Wickramasinghe et al. (2025) find that many public datasets used in NTC research contain unencrypted traffic due to collection before TLS 1.3 adoption. TLS 1.3 datasets in the corpus often contain deprecated cipher suites (3DES, RC4).

2. **Class imbalance.** ISCXVPN2016 and similar datasets exhibit significant class imbalance [wickramasinghe2025sok]. Barut et al. (2020) use SMOTE augmentation to address this, but imbalance remains an underreported evaluation factor.

3. **Sandbox bias.** Anderson & McGrew (2017) explicitly accommodate Windows XP-based sandbox bias in malware TLS datasets. Oh et al. (2021) acknowledge that sandbox-collected malware traffic may not reflect real-world TLS behavior.

4. **Dataset-specific shortcut features.** Wang et al. (2026) propose BiasSeeker to detect dataset-specific shortcut features across 19 public datasets. They find that SNI may be valid in application identification but fragile in malware detection—feature selection must be scenario-sensitive.

5. **Reproducibility barriers.** Akbari et al. (2022) evaluate on a real-world ISP dataset that is not publicly available, limiting independent reproduction.

### 5.3 Evaluation Methodology Flaws

**Critically documented by Wickramasinghe et al. (2025) and Zhao et al. (2025):**

1. **SNI data leakage.** Masking SNI causes substantial accuracy drops in many published classifiers, indicating overfitting to destination identifiers rather than traffic patterns.

2. **Per-packet split data leakage.** Splitting data by packet rather than by flow enables models to learn implicit flow IDs, inflating accuracy without learning generalizable patterns.

3. **Frozen encoder failures.** Representation learning models (ET-BERT, YaTC) perform poorly when encoders are frozen, indicating that reported high accuracy relies on fine-tuning that overfits to dataset-specific artifacts.

4. **Metric inflation.** Accuracy dominates reported metrics; false positive rates in realistic conditions are rarely provided.

### 5.4 Research Gap Statement

**Placeholder:** To be written after the matrix reaches the timeline gate (≥40 sources). Candidate gaps identified in cross-paper synthesis:
1. Independent academic validation of JA4 collision rates and stability.
2. No published study combining JA4/JA3S with flow-level behavioral features in a unified explainable scoring system.
3. Limited real-world SOC deployment studies with live traffic and reported false-positive rates.
4. ECH impact is mostly operational documentation; peer-reviewed quantitative measurements are emerging.
5. Limited XAI research specifically for TLS-fingerprint-based scoring combined with behavioral metadata.

### 5.5 Hypotheses to Test

Derived from the gap analysis and supported by corpus evidence:

1. **JA4 collision rates are lower than JA3 under extension shuffling.** (Supported by design rationale in althouse2023ja4; to be empirically validated.)

2. **Flow-level behavioral features (packet-size distributions, IAT patterns, beaconing scores) add discriminative power beyond JA4 fingerprints alone.** (Supported by akbari2022traffic, ramos2023cobalt, garcia2018efficient; fusion not yet evaluated.)

3. **Explainable ML (SHAP) can produce security-actionable explanations for JA4 + flow-feature decisions.** (Supported by grabowski2025explainable, singh2025interpretable; not yet tested on hybrid fingerprint-behavior models.)

4. **Concept drift in TLS traffic degrades JA4-based classifiers over time, requiring periodic retraining.** (Supported by malekghaini2022data, malekghaini2025drift.)

5. **ECH degrades JA4 coverage, but Outer ClientHello fields and behavioral metadata retain partial discriminative power.** (Supported by rfc9849, cisco2025ech; quantification absent.)

6. **Cross-dataset generalization of JA4 + flow-feature classifiers is poorer than within-dataset performance.** (Supported by wickramasinghe2025sok, malekghaini2022data.)

## Evidence Log

- wickramasinghe2025sok: SNI leakage, per-packet split shortcuts, frozen encoder failures, legacy dataset issues.
- zhao2025sugar: Representation learning pitfalls; data preparation problems inflate accuracy.
- wang2025bias: Dataset-specific shortcut features; SNI context-dependent validity.
- malekghaini2022data: Concept drift in DL encrypted traffic; traffic-shape models more resilient.
- malekghaini2025drift: MFWDD drift detection; SPLT features unstable over time.
- anderson2016deciphering: Sandbox bias in malware TLS datasets.
- oh2021survey: Survey acknowledgment of sandbox bias.

## Synthesis

**Established:**
- The literature contains widespread methodological flaws (SNI leakage, per-packet splits, frozen encoder failures) that inflate reported accuracy.
- Public datasets suffer from legacy issues, class imbalance, and reproducibility barriers.
- Concept drift is a real operational challenge requiring planned mitigation.

**Uncertain:**
- Whether ETTH can avoid these pitfalls while maintaining competitive accuracy.
- Whether JA4 + flow-feature fusion provides sufficient robustness under ECH and concept drift.

## Research Implications

- ETTH must adopt rigorous evaluation methodology from the outset: per-flow splits, SNI masking, frozen-encoder checks, modern datasets with TLS 1.3.
- Drift detection and model maintenance must be operational requirements.
- Dataset bias and shortcut learning must be explicitly tested using frameworks like BiasSeeker.
