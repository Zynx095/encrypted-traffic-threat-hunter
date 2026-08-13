# Research Design Summary

## 1. Research Problem

Network traffic is increasingly encrypted by default, making payload inspection infeasible. However, metadata survives encryption: flow-level statistics (packet sizes, inter-arrival times, byte ratios), TLS handshake parameters, and connection behaviors all carry discriminative signal. The literature establishes that metadata-only analysis is feasible [akbari2022traffic, oh2021survey, papadogiannaki2021survey], that malware TLS behavior differs from benign traffic [anderson2016deciphering], and that flow-level behavioral features detect encrypted C2 [ramos2023cobalt, zhang2025beacon, garcia2018efficient]. JA3 is foundational but insufficient alone [matousek2021reliability, matousek2025towards]; JA4 introduces design improvements but lacks independent validation [althouse2023ja4]. No published study in the current corpus combines JA4/JA3S fingerprints with flow-level behavioral features in a unified explainable scoring framework.

## 2. Primary Research Question

Does combining TLS fingerprint features (JA4/JA3S) with encrypted-flow behavioral features (packet-size distributions, inter-arrival times, byte ratios, multi-flow temporal patterns) provide statistically significant improvement in detection performance (F1-score and/or false-positive rate) compared to using either feature family in isolation?

## 3. Secondary Research Questions

1. What is the individual contribution of JA4 client fingerprints to detection performance, relative to JA3 client fingerprints?
2. What is the individual contribution of flow-level behavioral features to detection performance?
3. How does the combined JA4+flow configuration compare to combined JA3+flow in terms of precision, recall, F1-score, and false-positive rate?
4. Does explainability via SHAP reveal interpretable patterns that align with known malicious behaviors (e.g., low inter-arrival time variance for beaconing)?
5. How robust are the results across different public datasets (cross-dataset generalization)?
6. What is the computational overhead of feature extraction, training, inference, and SHAP explanation for each configuration?

## 4. Hypotheses

### Null Hypothesis (H0)
There is no statistically significant difference in detection performance (measured by F1-score and false-positive rate) between the combined JA4+flow feature configuration and either the flow-only or JA4-only configurations.

### Alternative Hypothesis (H1)
The combined JA4+flow feature configuration achieves statistically significant improvement in detection performance (F1-score and/or false-positive rate) compared to both the flow-only and JA4-only configurations.

**Important:** H1 does not claim that JA4 is superior to JA3, or that the combined approach will outperform all single-family baselines on every dataset. It states only that the combination provides measurable benefit over the isolated feature families. A null result is also a scientifically valid outcome.

## 5. Independent Variables

Five feature configurations:
1. Flow-only (packet-size stats, IATs, byte counts, packet counts, flow duration)
2. JA3-only (JA3 client + JA3S server fingerprints)
3. JA4-only (JA4 client + JA4S server fingerprints)
4. JA3 + flow
5. JA4 + flow

## 6. Dependent Variables

- Precision, recall, F1-score, ROC-AUC, false-positive rate
- Training time, inference time per flow, peak memory usage
- SHAP computation time, explanation stability (Jaccard similarity), feature attribution coherence

## 7. Controls

- Same dataset(s) and per-flow stratified train/test split
- Fixed random seed
- Identical classifier and hyperparameters across configurations
- Identical preprocessing and masking policy
- No test-set feature engineering or hyperparameter tuning
- Documented class distribution
- Multiple runs (≥3) with different seeds; mean and standard deviation reported

## 8. Experimental Configurations

| Exp | Configuration | Comparison Purpose |
|-----|---------------|-------------------|
| A | Flow-only | Behavioral baseline |
| B | JA3-only | Legacy fingerprint baseline |
| C | JA4-only | Current fingerprint baseline |
| D | JA3 + flow | Combined legacy baseline |
| E | JA4 + flow | Combined current standard (primary test) |

**Primary tests:**
- A vs. E: Does JA4 add value to flow features?
- C vs. E: Do flow features add value to JA4?
- D vs. E: Does JA4 improve upon JA3 in a combined setting?

## 9. Scope

This study will:
- Evaluate on public encrypted-traffic datasets.
- Use tree-based classifiers (Random Forest or XGBoost).
- Apply SHAP for explainability.
- Report detection performance and computational overhead.

This study will **not**:
- Decrypt payloads.
- Deploy in enterprise production environments.
- Claim universal malware detection.
- Guarantee attack identification.
- Conduct live internet surveillance.
- Use massive deep-learning architectures without rigorous evaluation.

## 10. Success Criteria

| Outcome | Interpretation |
|---------|---------------|
| Combined JA4+flow significantly outperforms both flow-only and JA4-only | Evidence supports H1; combination provides measurable benefit |
| Combined JA4+flow does not significantly outperform baselines | Null result; combination may be redundant or fusion method ineffective |
| JA4+flow significantly outperforms JA3+flow | JA4's design improvements translate to measurable gains |
| JA4+flow performs worse than expected | Important negative finding; JA4 collisions or ECH sensitivity may limit utility |
| SHAP explanations align with known malicious patterns | Evidence that combined model is interpretable by analysts |
| SHAP explanations are unstable or incoherent | Explainability limitation; analysts may not trust the system |

**A null result is a successful result if it is rigorously obtained and clearly reported.**

## 11. Major Assumptions

1. Public datasets contain sufficient TLS-encrypted traffic with both benign and malicious samples for meaningful evaluation.
2. Open-source JA3/JA4 extraction libraries are sufficiently accurate for experimental purposes.
3. Tree-based classifiers (Random Forest/XGBoost) are appropriate for the tabular feature vectors derived from flow and fingerprint data.
4. SHAP computation is feasible within project resource constraints for the selected dataset sizes.
5. The selected evaluation metrics (precision, recall, F1, FPR, ROC-AUC) are accepted by the target publication venue.

## 12. Major Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Insufficient malicious samples in public datasets | Medium | High | Use multiple datasets; undersample benign class if needed |
| JA4 library extraction errors | Medium | Medium | Validate against known JA4 hashes; fall back to JA3 if needed |
| Feature fusion provides no improvement | Low | Low | Null result is scientifically valid |
| SHAP overhead exceeds resources | Medium | Medium | Use TreeExplainer for tree models; sample test set |
| Dataset bias dominates results | Medium | High | Use multiple datasets; report per-dataset results; acknowledge limitations |

---

## Current Research Position

### What we currently believe based on literature

The literature strongly supports the following positions:

- **Metadata-only encrypted traffic analysis is feasible.** Flow statistics, packet-size distributions, IATs, and TLS handshake metadata carry sufficient signal for classification without payload decryption.
- **Flow-level behavioral features are validated detection signals.** Multiple peer-reviewed papers confirm that packet-size statistics, IAT patterns, CV of intervals, and multi-flow temporal features detect encrypted C2 and unknown attacks.
- **TLS fingerprinting is a mature but imperfect technology.** JA3 is widely used but suffers from collisions and instability; JA4 improves on JA3's design but lacks independent academic validation.
- **Tree-based models are appropriate for flow-feature classification.** Random Forest and XGBoost dominate the literature for tabular encrypted-traffic features.
- **Explainability via SHAP is established for flow-feature IDS.** SHAP provides coherent global explanations suitable for forensic reporting.
- **Evaluation rigor is critical.** SNI leakage, per-packet splits, and frozen-encoder failures inflate reported accuracy in many published studies.

### What we still need experiments to determine

The following questions remain unresolved and are the target of the proposed experimental work:

- **Does combining JA4 with flow-level behavioral features improve detection performance?** No published study evaluates this fusion.
- **Does JA4 consistently outperform JA3 in a combined framework?** Only one comparative study exists, and it does not evaluate JA4+flow fusion.
- **Can flow-level features compensate for reduced TLS visibility under ECH?** No study quantifies this compensation effect.
- **Is explainability via SHAP useful for hybrid fingerprint-behavior decisions?** Existing XAI work focuses on flow features alone; applicability to JA4+flow decisions is untested.
- **How robust is the combined approach across different datasets and network environments?** Cross-dataset generalization is poorly documented for any encrypted-traffic classifier.
- **What is the computational cost of the combined approach in practice?** Inference time and SHAP overhead at enterprise throughput are unreported for hybrid systems.

**The literature justifies investigating this combination. The experiments must determine whether the combination actually provides measurable benefit.**
