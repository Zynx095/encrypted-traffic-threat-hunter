# Repository Dependency Audit

**Date:** 2026-08-16
**Purpose:** Document the dependency graph between files, focusing on Python imports, script-to-module dependencies, and key execution relationships.

## Python Import Dependencies

### Pipeline Module Dependencies
```
pipeline/config.py
    ← (no imports, defines constants)

pipeline/hashing.py
    ← hashlib (standard library)
    ← pathlib (standard library)

pipeline/pcap_validator.py
    ← dpkt (third-party)
    ← pathlib (standard library)
    ← dataclasses (standard library)
    ← typing (standard library)

pipeline/flow_reconstruction.py
    ← socket (standard library)
    ← hashlib (standard library)
    ← typing (standard library)
    ← logging (standard library)
    ← dpkt (third-party)
    ← pipeline.tls_fingerprinting (local)

pipeline/tls_fingerprinting.py
    ← hashlib (standard library)
    ← typing (standard library)
    ← struct (standard library)

pipeline/feature_extraction.py
    ← numpy (third-party)
    ← typing (standard library)

pipeline/model_safe_generator.py
    ← pandas (third-party)
    ← typing (standard library)
    ← hashlib (standard library)
    ← time (standard library)

pipeline/experimental_dataset_constructor.py
    ← pandas (third-party)
    ← numpy (third-party)
    ← hashlib (standard library)
    ← time (standard library)
    ← sklearn.model_selection (third-party)

pipeline/manifest.py
    ← csv (standard library)
    ← json (standard library)
    ← pathlib (standard library)
    ← datetime (standard library)
    ← pipeline.config (local)

pipeline/ingestion.py
    ← logging (standard library)
    ← pathlib (standard library)
    ← datetime (standard library)
    ← typing (standard library)
    ← pipeline.config (local)
    ← pipeline.hashing (local)
    ← pipeline.pcap_validator (local)
    ← pipeline.adapters.base (local)
    ← pipeline.manifest (local)

pipeline/adapters/base.py
    ← abc (standard library)
    ← typing (standard library)
    ← pathlib (standard library)
```

### Adapter Dependencies
```
pipeline/adapters/ds004.py
    ← pipeline.adapters.base (local)

pipeline/adapters/ds006.py
    ← pipeline.adapters.base (local)

pipeline/adapters/ds007.py
    ← pipeline.adapters.base (local)

pipeline/adapters/ds008.py
    ← pipeline.adapters.base (local)
```

### Script Dependencies
```
step6_run.py
    ← os (standard library)
    ← glob (standard library)
    ← pandas (third-party)
    ← logging (standard library)
    ← pipeline.feature_extraction (local)

step6_validation.py
    ← os (standard library)
    ← pandas (third-party)
    ← numpy (third-party)
    ← pipeline.feature_extraction (local)
    ← logging (standard library)

step5_validation.py
    ← os (standard library)
    ← pandas (third-party)
    ← glob (standard library)
    ← json (standard library)

step65_step4_run.py
    ← os (standard library)
    ← csv (standard library)
    ← glob (standard library)
    ← logging (standard library)
    ← hashlib (standard library)
    ← pathlib (standard library)
    ← dpkt (third-party)
    ← pipeline.flow_reconstruction (local)
    ← pipeline.feature_extraction (local)
    ← pipeline.model_safe_generator (local)
    ← pipeline.experimental_dataset_constructor (local)
```

### Verification Script Dependencies
```
data/verification/verify_ds008.py
    ← dpkt (third-party)
    ← csv (standard library)
    ← os (standard library)
```

## Script-to-Module Execution Relationships

### Core Pipeline Execution Flow
```
ingestion.py
    ↓ (discovers PCAPs, extracts basic metadata, validates PCAPs)
pcap_validator.py
    ↓ (validates PCAP integrity and format)
flow_reconstruction.py
    ↓ (reconstructs bidirectional flows, extracts TLS handshakes)
tls_fingerprinting.py
    ↓ (extracts JA3, JA3S, JA4 fingerprints from handshakes)
feature_extraction.py
    ← (extracts behavioral and TLS features from flows)
model_safe_generator.py
    ← (generates leakage-controlled model-safe dataset and provenance)
experimental_dataset_constructor.py
    ← (splits data into Experiments A–E train/test sets)
```

### Verification Execution Flow
```
verify_ds008.py
    ↓ (analyzes PCAPs for TLS packet presence and basic characteristics)

step5_validation.py
    ↓ (validates JA3/JA4 extraction success rates on interim flow data)

step6_run.py
    ↓ (extracts behavioral features from interim flow data)

step6_validation.py
    ↓ (validates feature extraction results and checks constraints)

step65_step4_run.py
    ↓ (complete pipeline execution for expanded DS-008 corpus: ingestion → reconstruction → feature extraction → model-safe generation → experiment construction)
```

## Key Execution Relationships Summary

1. **Data Flow:** RAW PCAPS → INGESTION → VALIDATION → RECONSTRUCTION → FINGERPRINTING → FEATURE EXTRACTION → MODEL-SAFE → EXPERIMENTAL SPLITS
2. **Verification Flow:** PCAP VERIFICATION → INTERMEDIATE VALIDATION → FEATURE VALIDATION → COMPLETE PIPELINE VALIDATION
3. **Dependency Hierarchy:**
   - Core utilities (hashing, config) → Validation → Reconstruction → Fingerprinting → Feature Extraction → Model-Safe → Experiment Construction
   - Scripts orchestrate these modules in sequence
4. **Test Dependencies:** All test files import the pipeline modules they test

## Circular Dependencies: None detected

## External Dependencies
- **dpkt:** PCAP parsing (used in pcap_validator.py, flow_reconstruction.py)
- **pandas:** Data manipulation (used in model_safe_generator.py, experimental_dataset_constructor.py, feature_extraction.py, verification scripts)
- **numpy:** Numerical operations (used in feature_extraction.py, experimental_dataset_constructor.py)
- **scikit-learn:** GroupShuffleSplit for experimental splits (used in experimental_dataset_constructor.py)
- **All other dependencies are Python standard library**

## Files with No Dependencies (Leaf Nodes)
- Scripts that don't import other local modules:
  - `step65_step4_run.py` (imports pipeline modules)
  - Actually, all scripts import pipeline modules - there are no completely independent scripts

## Files Imported by Many Modules (Hub Nodes)
- `pipeline/config.py` - imported by ingestion.py, manifest.py
- `pipeline/manifest.py` - imported by ingestion.py
- Various pipeline modules import each other in the core pipeline sequence

## Conclusion
The dependency graph is well-structured and follows the expected data flow of the pipeline. There are no circular dependencies, and the external dependencies are appropriate for the domain (dpkt for PCAP parsing, pandas/numpy/scikit-learn for data analysis and ML preparation).