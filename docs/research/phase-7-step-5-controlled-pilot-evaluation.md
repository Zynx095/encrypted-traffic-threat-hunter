# Phase 7 Step 5: Controlled Source-Confounded Pilot Evaluation

## 1. Objective
The objective of this step is to execute a controlled pilot evaluation of the frozen Phase 6 feature extraction pipeline using a leakage-safe preprocessing and cross-validation framework. The goal is to prove the pipeline is mechanically robust and capable of handling five different experimental configurations.

## 2. Scientific Status
> [!WARNING]
> **NOT SUITABLE FOR GENERALIZATION CLAIMS**
> The results documented below are the product of a **SOURCE-CONFOUNDED PILOT**. Because the dataset consists almost exclusively of 2,543 Malicious flows (from Malware-Traffic-Analysis.net) against only 6 Benign flows (from CipherSpectrum), models are trivially separating the environmental differences between the two source datasets rather than learning generalized threat detection features.

## 3. Dataset Composition
- **MALICIOUS SOURCE**: DS-008 / Malware-Traffic-Analysis.net (2,543 flows)
- **BENIGN SOURCE**: DS-004 / CipherSpectrum (6 flows)
- **Class Ratio**: 424:1
- **Total Missing Values**: 55,661 (primarily non-existent sequence or structural features in UDP flows)

## 4. Splitting & Cross-Validation
- **Strategy**: `GroupShuffleSplit(n_splits=5, test_size=0.2, random_state=42)`
- **Grouping Key**: `behavioral_hash`
- **Integrity**: Verified that duplicate behavioral groups do not cross fold boundaries. `intersection(train_groups, test_groups) == empty` is strictly enforced.

## 5. Preprocessing & Leakage Control
- Transformers (imputers, scalers, categoric encoders) are explicitly fitted only on the `train` partitions using an `imblearn` pipeline.
- Fingerprints (`ja3_hash`, `ja4`) are treated as pure categorical strings and encoded using `OneHotEncoder` before entering tabular models.
- **Leakage Audit**: All provenance, IP, timestamp, index, and grouping keys were explicitly stripped out before model matrix generation.

## 6. Imbalance Handling
- Due to only possessing 6 benign samples, techniques like SMOTE and synthetic downsampling are mathematically infeasible inside CV loops (neighbors cannot be found).
- Baseline linear and tree algorithms employed native `class_weight='balanced'` inside the estimators.

## 7. Experimental Results

### Experiment A: Flow Only
- Sample Count: 2549
- Feature Count: 80
- Best Model: Logistic Regression (Avg PR-AUC: 1.0, Avg F1: 1.0)

### Experiment B: JA3 Only
- Sample Count: 200 (Reduced due to fingerprint availability)
- Feature Count: 1
- Best Model: Logistic Regression (Avg PR-AUC: 0.997, Avg F1: 0.982)

### Experiment C: JA4 Only
- Sample Count: 200
- Feature Count: 1
- Best Model: Logistic Regression / Random Forest (Avg PR-AUC: 0.998, Avg F1: 0.982)

### Experiment D: JA3 + Flow
- Sample Count: 200
- Feature Count: 81
- Best Model: Logistic Regression (Avg PR-AUC: 1.0, Avg F1: 0.997)

### Experiment E: JA4 + Flow
- Sample Count: 200
- Feature Count: 81
- Best Model: Logistic Regression (Avg PR-AUC: 1.0, Avg F1: 0.997)

## 8. Source-Confounding Analysis & Conclusion
The metrics approaching perfect precision and recall validate the pipeline's mechanical functionality. However, scientifically, the dataset is highly source-confounded.

**CONCLUSION:**
The experimental pipeline is **ENGINEERINGALLY VALID** but **SCIENTIFICALLY LIMITED BY SOURCE CONFOUNDING**. The pipeline is ready to execute generalized model training immediately once an independently provisioned Benign dataset is securely admitted.
