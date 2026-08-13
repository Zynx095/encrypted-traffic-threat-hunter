# Experimental Design

## 1. Comparison Matrix

The experimental design compares five feature configurations using identical classifiers, datasets, and evaluation protocols.

| Experiment | Feature Configuration | Purpose |
|------------|----------------------|---------|
| A | Flow-only | Baseline: encrypted-flow behavioral features alone |
| B | JA3-only | Baseline: TLS fingerprinting alone (legacy standard) |
| C | JA4-only | Baseline: TLS fingerprinting alone (current standard) |
| D | JA3 + flow | Combined: legacy fingerprint + behavioral features |
| E | JA4 + flow | Combined: current fingerprint + behavioral features |

**Primary comparisons:**
- A vs. E: Does adding JA4 to flow features improve performance?
- B vs. D: Does adding flow features to JA3 improve performance?
- C vs. E: Does adding flow features to JA4 improve performance?
- D vs. E: Does JA4 provide measurable improvement over JA3 when combined with flow features?

## 2. Datasets

Datasets will be selected from publicly available sources used in the literature:

| Dataset | Traffic Type | TLS Versions | Classes | Source |
|---------|-------------|--------------|---------|--------|
| ISCXVPN2016 | VPN / non-VPN application traffic | TLS 1.2 (implied) | 5+ | UCI / ISCX |
| CIC-Darknet2020 | Tor, malware, benign, streaming, VoIP, etc. | TLS 1.2 / 1.3 (implied) | 8+ | CIC |
| USTC-TFC2016 | Malware / benign | TLS 1.0 / 1.2 | 10+ | USTC |

**Dataset selection criteria:**
- Publicly available and reproducible.
- Contains TLS-encrypted traffic.
- Includes both benign and malicious samples.
- Has sufficient sample size for stratified per-flow train/test splits.

**Important caveat:** All public datasets have known limitations [wickramasinghe2025sok, wang2025bias]. Results will be interpreted with awareness of dataset-specific biases.

## 3. Classifiers

Following the literature [ugurlu2021classification, garcia2018efficient, akem2024realtime], the primary classifier will be **Random Forest** or **XGBoost** for tabular feature vectors. These models are:
- Well-supported by the literature for encrypted flow classification.
- Interpretable via SHAP.
- Computationally efficient for undergraduate-scale experimentation.
- Less prone to the evaluation flaws documented for deep learning [wickramasinghe2025sok, zhao2025sugar].

If resources permit, a secondary classifier (e.g., Logistic Regression as a linear baseline) may be added for additional context, but the primary comparison will use a single classifier family to isolate the effect of feature configuration.

## 4. Feature Extraction Pipeline

### Flow Features
- Extract flows from PCAP or dataset-provided flow records using Zeek or CICFlowMeter.
- Compute per-flow statistics: packet sizes (mean, std, min, max, quantiles), IATs (mean, std, min, max), byte counts (originating/responding), packet counts, flow duration.
- Mask or remove SNI, IP addresses, and cipher information where applicable to prevent canary feature reliance [akbari2022traffic, wickramasinghe2025sok].

### TLS Fingerprint Features
- Extract JA3/JA3S and JA4/JA4S fingerprints from TLS ClientHello/ServerHello packets using open-source libraries (e.g., ja3er/ja4, salesforce/ja3).
- For JA3: compute MD5 hash of ordered ClientHello fields (SSL Version, Ciphers, Extensions, Elliptic Curves, Elliptic Curve Formats).
- For JA4: compute human-readable fingerprint following the FoxIO specification [althouse2023ja4].
- Record presence/absence of SNI and ALPN as additional binary features.

### Combined Features
- Concatenate flow-feature vector with TLS-fingerprint feature vector (one-hot encoded or embedding-based).
- Ensure no feature leakage: TLS fingerprints are extracted from the handshake only, not from later packets that may overlap with flow feature windows.

## 5. Evaluation Protocol

- **Split:** Per-flow stratified train/test split (e.g., 70/30 or 80/20). Flows are shuffled with fixed random seed before splitting.
- **No test-set tuning:** Hyperparameters are selected via cross-validation on the training set only.
- **Metrics:** Precision, recall, F1-score, ROC-AUC, FPR, training time, inference time per flow.
- **Statistical testing:** Where applicable, use McNemar's test or paired t-tests to assess whether differences between configurations are statistically significant.
- **Explainability:** SHAP values computed for the test set of the best-performing combined configuration. Explanation stability assessed via Jaccard similarity of top-k features across repeated runs [grabowski2025explainable].

## 6. Fair Comparison Rules

The following rules ensure scientifically valid comparison:

1. **Identical dataset(s).** All configurations evaluated on the same train/test split.
2. **Per-flow splitting.** No per-packet splitting to prevent flow-ID shortcuts.
3. **Identical classifier and hyperparameters.** Same model type, same hyperparameters, same random seed.
4. **Identical preprocessing.** Flow extraction and masking applied uniformly.
5. **No test-set feature engineering.** All feature selection fit exclusively on training data.
6. **SNI masking.** SNI is masked in flow features unless deliberately studying SNI's contribution.
7. **Documented class distribution.** Train and test class counts reported for all configurations.
8. **Multiple runs.** At least 3 runs with different random seeds; mean and standard deviation reported.

**Why each rule matters:**
- Rules 1–4 isolate the effect of feature configuration from confounding factors.
- Rule 5 prevents optimistic bias.
- Rule 6 prevents overfitting to destination identifiers [wickramasinghe2025sok].
- Rule 7 ensures class imbalance is visible and comparable.
- Rule 8 ensures results are not dependent on a single lucky split.

## 7. Scope Limitations

This study will **not** attempt:

- **Payload decryption.** ETTH operates entirely on observable metadata.
- **Enterprise-scale deployment.** Evaluation is on public datasets; production SOC deployment is beyond scope.
- **Universal malware detection.** Evaluation is limited to the malware and application classes present in selected datasets.
- **Guaranteed attack identification.** No method can guarantee detection; ETTH measures relative improvement.
- **Live internet surveillance.** All evaluation uses captured datasets.
- **Massive deep-learning architectures.** Given evaluation flaws documented for DL on encrypted traffic [wickramasinghe2025sok, zhao2025sugar], tree-based models are preferred for rigor.
- **Production-scale distributed infrastructure.** Single-machine experimentation is the scope.

## 8. Success Criteria

A successful research project produces scientifically useful results regardless of whether the primary hypothesis is supported.

### If combined features outperform single-family baselines:
- Evidence supports the hypothesis that JA4+flow fusion provides measurable detection benefit.
- Quantify the improvement (e.g., F1 increase, FPR reduction).
- Identify which feature families contribute most via SHAP analysis.
- This would be a positive, publishable result.

### If combined features provide little or no improvement:
- That is also a scientifically valid and useful finding.
- It would suggest that the additional information from JA4/JA3S is redundant given flow features, or that the fusion method does not effectively leverage both signal families.
- This null result still advances the state of knowledge by preventing future researchers from duplicating an ineffective approach.

### If JA4 introduces unexpected failure modes:
- Collision rates, ECH sensitivity, or instability under extension randomization would be important findings.
- This would inform the broader TLS fingerprinting community about JA4's operational limitations.

### Minimum publishable result:
- Rigorous experimental comparison of at least three feature configurations (flow-only, TLS-only, combined) on at least one public dataset.
- statistically grounded conclusions about whether combination provides measurable benefit.
- Identification of one or more specific limitations or failure modes.
- Reproducible methodology and documented evaluation protocol.

## 9. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Public datasets lack sufficient malicious samples | Medium | High | Use multiple datasets; combine benign samples from different sources |
| JA4 extraction libraries are immature | Medium | Medium | Fall back to JA3 for experiments where JA4 fails; document limitations |
| Feature fusion provides no improvement | Low | Low | Null result is still scientifically valid |
| Computational resources insufficient for SHAP on large datasets | Medium | Medium | Use SHAP sampling or TreeExplainer for tree models; document overhead |
| Class imbalance skews results | Medium | Medium | Apply stratified splitting; report per-class precision/recall |
