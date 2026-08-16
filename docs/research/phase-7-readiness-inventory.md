# Phase 7 Readiness Inventory

**Date:** 2026-08-16
**Purpose:** Determine which existing files Phase 7 can directly reuse and what is still missing.

## Files Phase 7 Can Directly Reuse

### Dataset Inputs
- `data/processed/v2/model_safe/model_safe_dataset.parquet` — Leakage-controlled model-safe features (primary input)
- `data/processed/v2/provenance_metadata.parquet` — Provenance/audit data (for traceability)
- `data/processed/v2/experiments/` — Pre-split experimental datasets (A–E train/test splits)
  - `A_flow_only.parquet` / `A_flow_only_meta.parquet` — Flow-only experiments
  - `B_ja3_only.parquet` / `B_ja3_only_meta.parquet` — JA3-only experiments
  - `C_ja4_only.parquet` / `C_ja4_only_meta.parquet` — JA4-only experiments
  - `D_ja3_flow.parquet` / `D_ja3_flow_meta.parquet` — JA3+Flow experiments
  - `E_ja4_flow.parquet` / `E_ja4_flow_meta.parquet` — JA4+Flow experiments
- `data/manifests/v2/phase6_expanded_audit.json` — Experiment audit metadata

### Model-Safe Outputs (from Phase 6)
- All files in `data/processed/v2/model_safe/` and `data/processed/v2/experiments/` (see above)

### Experimental A–E Datasets
- All experiment split files listed above under Dataset Inputs

### Manifests
- `data/manifests/v2/phase6_expanded_audit.json` — Experiment execution audit
- `data/manifests/ds008_expanded_corpus_manifest.csv` — DS-008 corpus definition
- `data/manifests/model_safe_manifest.json` — Model-safe dataset manifest
- `data/manifests/experimental_dataset_manifest.json` — Experimental dataset manifest
- `data/manifests/phase6_final_audit.json` — Phase 6 final audit

### Feature Definitions
- `pipeline/feature_extraction.py` — Complete feature extraction logic
- `pipeline/tls_fingerprinting.py` — TLS fingerprint extraction (JA3, JA3S, JA4)
- `pipeline/flow_reconstruction.py` — Flow reconstruction logic

### Tests
- `tests/test_experiments.py` — Experiment validation tests (extensible)
- `tests/test_model_safe.py` — Model-safe validation tests (extensible)
- `tests/test_ingestion.py` — Ingestion validation tests
- `tests/test_flow_reconstruction.py` — Flow reconstruction validation tests
- `tests/test_tls_fingerprinting.py` — TLS fingerprint validation tests
- `tests/test_feature_extraction.py` — Feature extraction validation tests

### Research Specifications
- `docs/research/experimental-design.md` — Formal experimental design (A–E configurations)
- `docs/research/research-problem.md` — Central research question and hypotheses
- `docs/research/research-design-summary.md` — Research design summary
- `docs/research/final-dataset-decision.md` — Final dataset selection rationale
- `docs/research/dataset-selection-scorecard.md` — Dataset evaluation framework
- `docs/research/dataset-verification-queue.md` — Verification priorities and methods
- `docs/research/phase-6-master-audit.md` — Phase 6 completion audit

### Leakage Controls
- `pipeline/model_safe_generator.py` — Leakage-controlled filtering logic
- `pipeline/feature_extraction.py` — Feature extraction with identifier removal
- `docs/research/leakage-controls--model-safe-data` section in README.md — Documentation of leakage controls
- `docs/research/critical-scientific-limitations` section in README.md — Documentation of limitations

### Split Logic
- `pipeline/experimental_dataset_constructor.py` — GroupShuffleSplit-based splitting with behavioral_hash grouping
- `tests/test_experiments.py` — Tests for splitting logic

### Existing Configuration
- `pipeline/config.py` — Pipeline configuration (paths, constants, versions)
- `pipeline/__init__.py` — Package initialization
- `pipeline/adapters/` — Dataset adapter base class and specific adapters (DS-004, DS-006, DS-007, DS-008 templates)

## What Phase 7 Is Still Missing

### Expected Major Issue (Documented, Not Solved Here)
- **Extreme class imbalance:** 2543 MALICIOUS vs 6 BENIGN_VALIDATION rows (~424:1 ratio in model-safe data)
  - This is a known limitation documented in the README and research documents
  - Phase 7 must address this through appropriate techniques (resampling, cost-sensitive learning, etc.)
  - **Do NOT solveدرسة during cleanup — only document it**

### Missing Components for Phase 7
- **ML model implementations** — No models have been trained yet (expected for Phase 7)
- **Evaluation scripts** — No scripts for training/evaluating ML models on the experimental datasets
- **Interpretability tools** — No SHAP/LIME or other interpretability implementations (planned for Phase 7)
- **Results storage** — No dedicated directory for storing model artifacts, predictions, or evaluation results
- **Hypermutation tuning** — No automated hyperparameter tuning framework
- **Cross-validation scripts** — No scripts for running cross-validation experiments (beyond the initial train/test split)
- **Performance metrics calculation** — No scripts for calculating accuracy, F1, ROC-AUC, precision, recall, etc. beyond basic counts

### Recommended Preparations for Phase 7
1. **Create ML model directory:** `ml/models/` for storing trained models
2. **Create evaluation scripts:** Scripts for training and evaluating models on Experiments A–E
3. **Create results directory:** `ml/results/` for storing predictions, metrics, and visualizations
4. **Create interpretation directory:** `ml/interpretation/` for SHAP/LIME analyses
5. **Update .gitignore:** Add appropriate ignores for ML artifacts (already partially done)
6. **Document ML approach:** Decide on algorithms to evaluate (Random Forest, XGBoost, Neural Networks, etc.)
7. **Plan class imbalance strategy:** Research and document techniques for handling extreme imbalance
8. **Plan validation strategy:** Determine cross-validation approach and statistical tests

## Readiness Assessment: READY_WITH_CONDITIONS

Phase 7 can directly reuse all pipeline outputs, manifests, feature definitions, and research specifications. The primary blocker is the extreme class imbalance ratio (~424:1), which is a known scientific limitation that must be addressed during Phase 7 through appropriate ML techniques — not something to be "fixed" by deleting data or altering the experimental design.

All necessary inputs exist; Phase 7 consists of applying ML techniques to the existing experimental datasets.