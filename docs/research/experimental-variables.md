# Experimental Variables

## Independent Variables

The independent variable is the **feature configuration** used to train and evaluate the classifier. Five configurations are defined:

### Configuration 1: Flow-only
- **Features:** Packet-size statistics (mean, std, min, max, quantiles), inter-arrival times (mean, std, min, max), byte counts (originating/responding), packet counts, flow duration, direction sequences.
- **Rationale:** Establishes baseline performance using only encrypted-flow behavioral metadata, consistent with the feature families validated in garcia2018efficient, akem2024realtime, martinramos2022cobalt, and ramos2023cobalt.

### Configuration 2: TLS-fingerprint-only (JA4)
- **Features:** JA4 client fingerprint, JA4S server fingerprint, cipher suite list, extension count, ALPN presence, TLS version.
- **Rationale:** Establishes baseline performance using only TLS handshake metadata, following the JA4 specification [althouse2023ja4] and the comparative study by matousek2025towards.

### Configuration 3: TLS-fingerprint-only (JA3)
- **Features:** JA3 client fingerprint, JA3S server fingerprint.
- **Rationale:** Provides a direct comparison point against JA4 using the same classifier and dataset, following the JA3/JA3S specification [althouse2017ja3, althouse2019ja3s].

### Configuration 4: Combined JA4 + flow
- **Features:** All features from Configuration 1 plus all features from Configuration 2.
- **Rationale:** Tests the central research question: does combining JA4 fingerprints with flow-level behavioral features improve detection performance beyond either family alone?

### Configuration 5: Combined JA3 + flow
- **Features:** All features from Configuration 1 plus all features from Configuration 3.
- **Rationale:** Provides a direct comparison against JA4+flow to determine whether JA4's design improvements translate to measurable performance gains in a combined framework.

## Dependent Variables

Dependent variables are the measurable outcomes used to evaluate each configuration:

### Classification Performance
- **Precision:** Proportion of predicted positives that are true positives.
- **Recall:** Proportion of true positives that are predicted positive.
- **F1-score:** Harmonic mean of precision and recall.
- **ROC-AUC:** Area under the receiver operating characteristic curve.
- **False-Positive Rate (FPR):** Proportion of benign samples incorrectly classified as malicious.

These metrics are standard in the literature [ugurlu2021classification, singh2025interpretable, wickramasinghe2025sok] and allow direct comparison with prior work.

### Computational Performance
- **Training time:** Wall-clock time to train the classifier on the training set.
- **Inference time per flow:** Average wall-clock time to classify one flow.
- **Peak memory usage:** Maximum memory consumed during training or inference.

Computational performance is relevant because ETTH targets SOC deployment where throughput matters [akem2024realtime].

### Explainability Metrics
Explainability will be assessed using SHAP (SHapley Additive exPlanations), following singh2025interpretable and grabowski2025explainable. The following metrics from the XAI-IDS literature will be used where applicable:

- **SHAP computation time:** Wall-clock time to compute SHAP values for the test set. High overhead may limit real-time usability [singh2025interpretable, grabowski2025explainable].
- **Explanation stability (Jaccard similarity):** Consistency of top-k feature attributions across repeated runs with fixed random seed. Lower stability indicates explanations are unreliable [grabowski2025explainable].
- **Feature attribution coherence:** Whether SHAP highlights features that align with known malicious patterns (e.g., low inter-arrival time variance for beaconing). This is a qualitative metric assessed by domain experts or documented heuristics.

**Important:** No custom explainability metric will be invented. Only metrics established in the XAI literature will be used.

## Control Variables

The following variables must be held constant across all experimental configurations to ensure a fair comparison:

### Dataset and Split
- **Same dataset(s):** All configurations are evaluated on identical dataset(s) to eliminate dataset bias [wickramasinghe2025sok, wang2025bias].
- **Per-flow train/test split:** Flows, not packets, are the unit of splitting. Per-packet splitting is prohibited because it enables flow-ID shortcut learning [wickramasinghe2025sok, zhao2025sugar].
- **Stratified split:** Class distribution is preserved in train and test sets.
- **Fixed random seed:** Ensures reproducibility of train/test partitioning and model initialization.

### Preprocessing
- **Identical preprocessing pipeline for flow features:** Packet captures are processed through the same flow extractor (e.g., Zeek or CICFlowMeter) with identical parameters.
- **Identical masking policy:** SNI and other canary features are masked or removed from flow features where applicable, following akbari2022traffic and wickramasinghe2025sok.
- **No test-set feature engineering:** All feature selection and engineering is fit exclusively on the training set.

### Classifier and Training
- **Identical classifier(s):** The same model architecture and hyperparameters are used for all configurations. For tree-based models, this means identical n_estimators, max_depth, etc. For deep learning, identical layer sizes, learning rates, and epochs.
- **No test-set hyperparameter tuning:** Hyperparameters are selected using only the training set (e.g., cross-validation on training data) and fixed before test-set evaluation.
- **Identical evaluation metrics:** Precision, recall, F1, ROC-AUC, and FPR are computed on the same test set for all configurations.

### Environment
- **Same hardware/environment:** Training and inference are performed on the same machine to ensure comparable timing measurements.
- **Documented class distribution:** The number of benign and malicious samples in train and test sets is recorded for all configurations.

## Why Controls Are Necessary

| Control | Reason |
|---------|--------|
| Per-flow split | Prevents data leakage via flow-ID shortcuts [wickramasinghe2025sok, zhao2025sugar] |
| SNI masking | Prevents overfitting to destination identifiers rather than traffic patterns [wickramasinghe2025sok] |
| Fixed random seed | Ensures reproducibility and eliminates random variation as a confounding factor |
| Same classifier | Isolates the effect of feature configuration from model selection |
| No test-set tuning | Prevents optimistic bias in performance estimates |
| Stratified split | Ensures class imbalance does not differentially affect configurations |
