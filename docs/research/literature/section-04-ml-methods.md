# Section 4 — ML Methods for Encrypted Traffic Classification

## Objective

Survey supervised and deep-learning algorithms, representation-learning techniques, explainability methods, and evaluation protocols relevant to ETTH's ML engine.

## Research Questions

- Which algorithms achieve state-of-the-art results on encrypted traffic classification benchmarks?
- How do deep-learning architectures (CNN, LSTM, GNN) compare to tree-based methods?
- What explainability methods produce security-actionable explanations for network traffic classifiers?
- How is concept drift measured and mitigated in production network ML systems?

## Subsections

### 4.1 Supervised Learning: Random Forest, XGBoost, Deep Forest

**Random Forest:**
- Most widely used baseline for encrypted flow classification [garcia2018efficient, akem2024realtime, martinramos2022cobalt, ugurlu2021classification].
- Garcia et al. (2018) pair RF with KSD histogram features for encrypted video/VoIP classification.
- Akem et al. (2024) achieve 87.2–95.3% accuracy in-switch using RF with packet-size and IAT features.
- Martin Ramos et al. (2022) use RF for Cobalt Strike detection, achieving ~50% TPR with 1.4% FPR—chosen for low false-positive deployment suitability.

**XGBoost:**
- Reported as top performer on flow-feature datasets [ugurlu2021classification, singh2025interpretable].
- Ugurlu et al. (2021) report 94.53% accuracy for non-VPN encrypted traffic on ISCX VPN-nonVPN.
- Singh et al. (2025) apply XGBoost with SHAP for encrypted traffic anomaly detection, achieving 99.94% peak accuracy on CIC-Darknet2020.
- Malekghaini et al. (2025) use XGBoost with SPLT features for drift detection, finding basic XGBoost not stable over long periods.

**Deep Forest (CaForest):**
- Zhang et al. (2022) propose DF-IDS, integrating RF and Extra Trees (20 trees each), achieving 94.9% accuracy and 94.4% M-DR with 0.70% M-FAR on 9-class SSL/TLS encrypted malicious traffic.
- Outperforms DL baselines on small-scale unbalanced data without requiring large datasets.

**Important caveat:** Model superiority is context-dependent. XGBoost excels on some flow-feature tasks; neural networks excel on multi-flow C2 detection [ramos2023cobalt]; deep forest excels on small-scale unbalanced data. No single model dominates across all datasets and tasks.

### 4.2 Deep Learning: CNN, LSTM

**CNN/LSTM architectures:**
- Akbari et al. (2022) combine stacked LSTM (3 layers, bidirectional) for flow time-series features (packet sizes, directions, IATs) with 1D CNN as an alternative. Fully connected network processes flow statistics. Achieves >95% accuracy on ISP mobile traffic and 99% on QUIC dataset.
- Malekghaini et al. (2022) use CNN+LSTM for encrypted web traffic classification, finding that traffic-shape models are more resilient to drift than TLS-header models.

**Critical evaluation:**
- Wickramasinghe et al. (2025) reveal that many reported DL results rely on legacy datasets, SNI data leakage, and per-packet split shortcuts. When evaluated with frozen encoders, representation learning models often perform poorly (<30% accuracy).
- Zhao et al. (2025) confirm that pre-trained representation learning models (BERT-based, T5-based) produce non-informative representations when encoder is frozen; reported high accuracy relies on per-packet data leakage and unfrozen encoders.

**Conclusion:** Deep learning architectures can achieve high accuracy, but reported results must be validated against proper evaluation methodology (per-flow splits, SNI masking, frozen-encoder checks).

### 4.3 Representation Learning and Autoencoders

**Pitfalls identified:**
- Zhao et al. (2025) show that representation learning models for encrypted traffic classification suffer from data preparation problems that create spurious performance improvements.
- Per-packet splits allow flow-ID shortcuts; models learn implicit flow IDs rather than traffic patterns.
- Pcap-Encoder (T5-based) is the only model providing an instrumental representation, but its complexity questions practicality.

**For ETTH:** If representation learning is considered, frozen-encoder evaluation must be standard practice to verify representation quality.

### 4.4 Explainability: SHAP, LIME, Feature Importance

**SHAP:**
- Singh et al. (2025) apply SHAP with XGBoost, Random Forest, and Isolation Forest for encrypted traffic anomaly detection. SHAP reveals most influential traffic features per attack class and provides model-agnostic explanations.
- Grabowski & Xu (2025) find SHAP superior for forensic reporting: provides coherent global explanations and is preferred for validation and auditing.

**LIME:**
- Grabowski & Xu (2025) find LIME useful for rapid local explanations during incident response, but note computational overhead at scale and lower stability than SHAP.
- Complementary use recommended: SHAP for global/forensic analysis, LIME for exploratory/local analysis.

**Limitation:** Existing XAI-IDS work focuses on flow-feature-based models (CICFlowMeter, UNSW-NB15 features). No source addresses explainability for decisions that primarily hinge on JA4/JA3 hashes combined with behavioral metadata.

### 4.5 Cross-Dataset Generalisation and Transfer Learning

**Poor generalization is documented:**
- Malekghaini et al. (2022) show that DL models trained on old data degrade when tested on new data. Traffic-shape models are more resilient than TLS-header models.
- Rosetta (referenced in corpus context) demonstrates up to 53% accuracy drop when models are tested in different network environments due to TCP mechanism effects on packet-length sequences.
- Wickramasinghe et al. (2025) show that many published classifiers fail on modern encrypted traffic because they were trained on legacy datasets containing unencrypted traffic or deprecated cipher suites.

**No successful transfer-learning cases are identified in the corpus.**

### 4.6 Concept Drift and Temporal Evaluation

**Drift is real and measurable:**
- Malekghaini et al. (2022) study data drift effects on DL encrypted traffic classifiers. Model performance degrades when trained on old data and tested on new data. Application-layer protocol selection affects robustness. Manual architectural adaptation improves convergence on new datasets.
- Malekghaini et al. (2025) propose MFWDD (Model-based Feature Weight Drift Detection) and a unified dataset stability benchmarking workflow. SPLT features show many data drifts over long periods; basic XGBoost with SPLT is not stable over time.

**Operational implication:** ETTH must plan for model maintenance, drift detection, and periodic retraining from the outset. Automatic drift adaptation remains an open problem.

## Evidence Log

- wickramasinghe2025sok: 348 occlusion experiments; SNI leakage causes overfitting; per-packet split enables shortcuts; frozen encoder evaluation essential.
- malekghaini2022data: DL model performance degrades across datasets and time; traffic-shape models more resilient than TLS-header models.
- malekghaini2025drift: MFWDD drift detection; SPLT features unstable over time; XGBoost requires retraining.
- singh2025interpretable: XGBoost + SHAP achieves 99.94% accuracy; model-agnostic framework; SHAP reveals feature importance per attack class.
- grabowski2025explainable: SHAP superior for forensic reporting; LIME for local incident response; complementary use recommended.
- ugurlu2021classification: XGBoost 94.53% accuracy on ISCX VPN-nonVPN; outperforms DT and RF.
- zhang2022deepforest: Deep forest 94.9% accuracy on small-scale unbalanced SSL/TLS data; outperforms DL baselines.
- zhao2025sugar: Representation learning fails with frozen encoders; per-packet split enables shortcuts; Pcap-Encoder only model with instrumental representation.
- wang2025bias: BiasSeeker detects shortcut features across 19 datasets; SNI valid in app ID but fragile in malware detection.

## Synthesis

**Established:**
- Random Forest and XGBoost are the most commonly used models for tabular flow-feature-based encrypted traffic classification.
- Deep learning (CNN, LSTM) achieves high reported accuracy, but many results are inflated by evaluation flaws (SNI leakage, per-packet splits, legacy datasets).
- SHAP is the preferred explainability method for global and forensic analysis; LIME complements it for local incident response.
- Concept drift is a real phenomenon: model performance degrades when trained on old data and tested on new data or in different network environments.
- Cross-dataset generalization is poor for many published models.

**Uncertain:**
- Whether any model is universally superior across datasets, feature sets, and detection targets.
- How to efficiently compute SHAP/LIME explanations at line rate in high-throughput networks.
- Whether representation learning can be made practical with proper evaluation methodology.

## Research Implications

- ETTH should adopt tree-based models (XGBoost or Random Forest) as primary classifiers, given their strong performance on flow features and interpretability via SHAP.
- Deep learning architectures may be considered for specific sub-tasks but must be validated with rigorous evaluation methodology (frozen encoders, per-flow splits, SNI masking).
- Explainability via SHAP should be integrated from the outset, with awareness of computational overhead.
- Drift detection and model maintenance must be planned as operational requirements, not afterthoughts.
