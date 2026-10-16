# ETTH Research Reproducibility & Replication Guide

**Project:** Encrypted Traffic Threat Hunter (ETTH)  
**Branch:** `research/phase-12-paper-manuscript`  
**Date:** October 16, 2026  

---

## 1. System Requirements & Environment Setup

### Software Requirements
- **Operating System:** Windows 10/11 or Ubuntu 22.04 LTS
- **Python:** 3.12.x (Verified on 3.12.0 64-bit)
- **Node.js (for UI dashboard):** 18.x or 20.x LTS

### Core Python Dependencies
```bash
pip install -r backend/requirements.txt
```
Key packages:
- `fastapi>=0.110.0`
- `uvicorn>=0.28.0`
- `pydantic>=2.0.0`
- `websockets>=12.0`
- `pandas>=2.0.0`
- `numpy>=1.24.0`
- `pyarrow>=14.0.0`
- `scikit-learn>=1.3.0`
- `xgboost>=2.0.0`
- `imbalanced-learn>=0.11.0`
- `dpkt>=1.9.8`
- `scapy>=2.5.0`
- `pytest>=8.0.0`

---

## 2. Deterministic Reproducibility Controls

To prevent data leakage and guarantee exact experimental replication:
1. **Random Seed:** All random operations (e.g. `GroupShuffleSplit`, `RandomForestClassifier`, `XGBClassifier`) are locked to seed **`42`**.
2. **Behavioral Hash Grouping:** GroupShuffleSplit is keyed on `behavioral_hash` (the SHA-256 digest of the 80 behavioral features) to guarantee that duplicate malware beaconing flows never appear in both training and test splits.
3. **Training-Only Preprocessing:** All imputation, standard scaling, and one-hot encodings are fitted strictly within training partitions via `imblearn.pipeline.Pipeline`. Test partitions are evaluated blindly using frozen transformers.

---

## 3. Step-by-Step Replication Runbook

### Step 1: Validate Source PCAP Hashes & Protected Archives
Verify that the 9 MTA stage 6.5 candidate archives match their SHA-256 provenance records:
```powershell
Get-ChildItem -Path "data/verification/mta_stage65/*.zip" | Get-FileHash -Algorithm SHA256
```

### Step 2: Run Automated Test Suite
Ensure all unit and integration tests pass cleanly:
```bash
python -m pytest tests/ -v
```
Expected output: 143+ tests passing across PCAP ingestion, flow reconstruction, TLS fingerprint extraction, model-safe leakage constraints, and multi-sensor adapters.

### Step 3: Execute Controlled Pilot Evaluation (Phase 7 Step 5)
```bash
python step7_step5_pilot_run.py
```
This script executes:
1. 5-fold `GroupShuffleSplit` across Tracks A, B, C, D, and E.
2. In-fold leakage audit (confirming zero IP, port, timestamp, or identifier columns in feature matrices).
3. Evaluates Logistic Regression, Random Forest, and XGBoost.
4. Outputs fold-by-fold metrics to `data/experiments/phase7_step5_pilot/pilot_fold_results.csv` and summary statistics to `pilot_summary.json`.

---

## 4. Replicating the Sensor Ingestion Pipelines (Phase 11)

Verify Zeek, Suricata, and eBPF ingestion pipelines against synthetic software test fixtures:
```bash
python -m pytest tests/test_sensors_zeek.py \
                 tests/test_sensors_suricata.py \
                 tests/test_sensors_ebpf.py \
                 tests/test_sensors_pipeline_integration.py -v
```

---

## 5. Artifact & Provenance Directory Structure

```
data/
├── verification/
│   ├── mta_stage65/                 # 9 Protected MTA malware archives
│   └── results/                     # Empirical PCAP verification CSVs
├── manifests/
│   ├── ds008_expanded_corpus_manifest.csv # Full metadata & SHA-256 hashes
│   ├── phase6_final_audit.json     # Phase 6 closure audit
│   └── phase7_step2_statistical_audit.json # Confounding & missingness audit
└── experiments/
    └── phase7_step5_pilot/         # Pilot cross-validation outputs
        ├── pilot_fold_results.csv
        └── pilot_summary.json
```
