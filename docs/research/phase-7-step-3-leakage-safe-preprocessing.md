# Phase 7 Step 3 — Leakage-Safe Preprocessing

## 1. Objective
Establish a reproducible, leakage-free preprocessing pipeline. Because the empirical validation of new benign data remains **BLOCKED** (no human-provisioned PCAPs are available), this step is formally operating as a **SOURCE-CONFOUNDED PILOT**. The preprocessing logic is constructed to survive strict scrutiny for leakage once valid benign data is obtained.

## 2. Leakage-Safe Architecture
All data transformations must occur inside a cross-validation fold, using the `imblearn.pipeline.Pipeline` module.
- `fit_transform` on the entire dataset is explicitly forbidden.
- The pipeline isolates:
  - Missing-value imputation
  - Scaling
  - Feature selection/encoding (if applicable)
  - Class resampling (e.g. SMOTE)

## 3. Missing-Value Policy
- **Continuous Features**: Missing values (e.g. absent TCP flags in UDP traffic, missing flow metrics) are imputed using the **median** of the training split. This avoids structural zero assumptions.
- **Categorical Features**: Missing values in JA3, JA3S, and JA4 are explicitly treated as semantic absences using a string constant `"Missing"`.

## 4. Scaling
- Scaling is implemented using `StandardScaler` (or `RobustScaler` dynamically) for all continuous flow features.
- Scalers are fitted **only** on the training set to prevent global feature statistics from leaking into the test evaluation.
- Tree-based baseline models may omit scaling, but linear models (Logistic Regression) will enforce it.

## 5. Resampling Strategies (Class Imbalance)
Because the dataset sits at an extreme 424:1 class imbalance, resampling must occur safely.
- Any SMOTE or random undersampling strategy is injected directly as a step inside the `imblearn` pipeline.
- This guarantees resampling is only performed on the training split, leaving the test split physically untouched and reflective of the original imbalance profile.

## 6. Categorical Handling
- Hash signatures (e.g., JA3 hashes) must remain as strings throughout preprocessing.
- To use SMOTE with these categorical signatures, one-hot encoding or ordinal encoding must be implemented inside the pipeline prior to the SMOTE step, or alternatively, experiments can evaluate non-categorical variants (Flow-Only) first.

## 7. Next Steps
Move to Pilot Modeling Readiness to configure baseline estimators and the evaluation framework.
