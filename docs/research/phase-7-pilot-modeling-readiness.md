# Phase 7 — Pilot Modeling Readiness

## 1. Objective
Establish the pilot modeling infrastructure necessary for methodological comparison across the five Experimental Tracks (A-E). Because the class imbalance (424:1) and source confounding (MTA vs CipherSpectrum) persist without new empirical benign data, this framework explicitly enforces **SOURCE-CONFOUNDED PILOT** labels on all evaluations. The purpose of the pilot is pipeline correctness and methodological stress-testing, not generalizable security claims.

## 2. Experimental Tracks
The framework maintains the frozen configurations:
- **Experiment A**: Flow Only
- **Experiment B**: JA3 Only
- **Experiment C**: JA4 Only
- **Experiment D**: JA3 + Flow
- **Experiment E**: JA4 + Flow

## 3. Pilot Models
The baseline modeling architectures include:
1. **Logistic Regression**: Linear baseline with `class_weight='balanced'`. Requires scaled inputs and explicit SMOTE/undersampling strategies for comparison.
2. **Random Forest**: Tree-based baseline which is highly resistant to monotonic transformations (scaling). Provides intrinsic feature importance measures.
3. **XGBoost**: Gradient boosting framework serving as the high-capacity standard.

## 4. Evaluation Metrics
Raw accuracy is scientifically meaningless with a 424:1 imbalance. The evaluation standard relies heavily on precision-recall mechanics:
- **PRIMARY: PR-AUC (Precision-Recall AUC)** - Ideal for severely imbalanced datasets.
- **Precision & Recall** - Crucial for analyzing False Positive vs False Negative tradeoffs in threat hunting.
- **F1 Score** - The harmonic mean of precision and recall.
- **Balanced Accuracy** - Adjusts accuracy mathematically for imbalanced classes.
- **Confusion Matrix** - Raw classification distribution.

## 5. Group-Aware Cross-Validation
All model evaluations occur through `GroupShuffleSplit(n_splits=5, test_size=0.2, random_state=42)` grouped rigidly on `behavioral_hash`. This ensures duplicate interactions from the identical underlying capture artifacts never cross between the train and test splits.

## 6. Scientific Limitation & Stop Condition
> [!WARNING]
> **NOT SUITABLE FOR GENERALIZATION CLAIMS**
> The evaluations produced by this pilot infrastructure remain scientifically crippled by source-confounding. A model reporting 99% PR-AUC is likely learning the environmental differences between the UNB lab and the MTA sandbox, not universal malware TLS features.
>
> Final model training and generalization claims MUST NOT START until Step 4 (Benign Dataset Validation) is resolved.
