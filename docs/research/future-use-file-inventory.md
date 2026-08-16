# Future Use File Inventory

**Date:** 2026-08-16
**Purpose:** Identify files not currently needed but potentially useful in future phases.

## PHASE 7 — MACHINE LEARNING / EXPERIMENTAL EVALUATION

### Potentially Useful Files:
- `pipeline/experimental_dataset_constructor.py` — Core experiment splitting logic (will be directly used)
- `pipeline/model_safe_generator.py` — Model-safe dataset generation (will be directly used)
- `pipeline/feature_extraction.py` — Feature extraction pipeline (will be directly used)
- `tests/test_experiments.py` — Experiment validation tests (will be extended)
- `tests/test_model_safe.py` — Model-safe validation tests (will be extended)
- `data/processed/v2/model_safe/` — Model-safe datasets (direct input to Phase 7)
- `data/processed/v2/experiments/` — Experimental dataset splits (direct input to Phase 7)
- `docs/research/final-dataset-decision.md` — Dataset selection rationale (informs Phase 7 choices)
- `docs/research/dataset-selection-scorecard.md` — Dataset evaluation criteria (informs Phase 7)
- `docs/research/dataset-verification-queue.md` — Verification priorities (informs Phase 7 preparation)

## PHASE 8 — MODEL INTERPRETABILITY

### Potentially Useful Files:
- `pipeline/feature_extraction.py` — Feature definitions (for SHAP/LIME explanations)
- `pipeline/tls_fingerprinting.py` — TLS fingerprint extraction (for interpretability of JA3/JA4)
- `docs/research/literature/section-04-ml-methods.md` — ML methods documentation (baseline for interpretability work)
- `docs/research/literature/section-05-challenges-and-gaps.md` — Challenges documentation (informs interpretability approach)
- Experimental outputs from Phase 7 (model weights, predictions, etc.)

## PHASE 9 — GENERALIZATION

### Potentially Useful Files:
- `docs/research/dataset-registry.csv` — Dataset registry (for identifying new datasets)
- `docs/research/dataset-selection-scorecard.md` — Evaluation framework (for evaluating new datasets)
- `docs/research/dataset-verification-queue.md` — Verification methodology (for verifying new datasets)
- `docs/research/literature/` — Literature review (for identifying new datasets and techniques)
- `pipeline/ingestion.py` — PCAP ingestion (for ingesting new datasets)
- `pipeline/adapters/` — Dataset adapters (templates for new dataset adapters)

## PHASE 10 — DEPLOYMENT

### Potentially Useful Files:
- `pipeline/config.py` — Configuration management (for deployment configuration)
- `pipeline/manifest.py` — Manifest generation (for deployment audit trails)
- `pipeline/hashing.py` — Hashing utilities (for deployment provenance)
- `docs/research/final-dataset-strategy.md` — Dataset strategy (for deployment planning)
- `docs/research/phase-6-ingestion-architecture.md` — Architecture documentation (for deployment planning)
- Model artifacts from Phase 7 (for deployment)

## Files with Broad Future Value:
- `docs/research/` — All research documentation (historical context, methodology, lessons learned)
- `pipeline/` — All pipeline modules (reusable components for similar projects)
- `tests/` — Test suite (regression testing for future changes)
- `README.md` — Project overview (onboarding for future contributors)