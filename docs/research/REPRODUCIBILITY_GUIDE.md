# ETTH Reproducibility Guide (Phases 8-10)

All commands run from the repository root with Python 3.12 (tested with the versions listed in §6).
Every step is deterministic given its inputs and seeds, except wall-clock timings.

## 1. Inputs

| Input | Location | How to obtain | Integrity |
|---|---|---|---|
| DS-008 MTA archives (9, tracked) | `data/verification/mta_stage65/*.zip` | in repository | SHA-256 recorded in `docs/research/PHASE_8_9_10_INITIAL_STATE_AUDIT.md` |
| DS-008 missing PCAP archives | `data/raw/acquisition_staging/mta/MTA-C0{21,37,46}.pcap.zip` | URLs in `data/corpus/capture_plan.json` (`acquisition.url`) | extracted PCAP SHA-256 in `capture_plan.json` (`expected_sha256`) |
| DS-009 / DS-011 Stratosphere PCAPs | `data/raw/acquisition_staging/{stratosphere_malware,ctu_normal}/…` | URLs in `capture_plan.json`; the MCFP attribution terms apply | no published checksum; SHA-256 recorded at first verification in `data/corpus/artifact_manifest.json` |
| DS-004 CipherSpectrum samples | `data/samples/ds004/sample1-6.pcap` | provider form (see PHASE_8 §2.1) | SHA-256 in `data/manifests/dataset_manifest_20260815_092018.csv` |

Raw data is git-ignored. The acquisition log is `data/raw/acquisition_staging/acquisition_log.tsv`; its content is also embedded in `capture_plan.json`.

## 2. Pipeline

```bash
# Phase 8: corpus v3 (resumable; interim per-capture tables keyed by raw SHA-256)
python -m pipeline.corpus all           # seed + plan + build + admit   (~13 min build, measured)
python -m pipeline.corpus replay-set    # 5,840-row replay table for the live stream

# Phase 9: diagnostics and benchmark suites (EXPLORATORY)
python -m ml coverage
python -m ml suite pooled_capture_cv
python -m ml suite matched_lab_capture_cv
python -m ml suite leave_one_source_out
python -m ml suite source_identifiability
python -m ml suite leave_one_family_out
python -m ml suite legacy_behavioral_holdout
python -m ml suite encoding_ablation
python -m ml unseen --suite-id <pooled suite id> --track C_JA4 --model logreg
python -m ml explain --suite-id <pooled suite id> --track A_FLOW --model random_forest

# Phase 10: sequence models (CPU)
python -m ml sequence --epochs 30
python -m ml sequence --epochs 30 --datasets DS-009,DS-011

# Deployable research-pilot models (optional) and report
python -m ml train-deployable --suite-id <pooled suite id> --track E_JA4_FLOW --model random_forest
python -m ml activate --model-id etth-e_ja4_flow-random_forest --version 1 --reason "..."
python -m ml report
python -m ml repro-package --suite-id <suite id>
```

The same jobs can be submitted from the Research Workbench (`/workbench`, Jobs tab) or via `POST /api/research/jobs`.
They run as separate, low-priority processes, one at a time.

## 3. Seeds and determinism

| Component | Seed / rule |
|---|---|
| Capture-balanced evaluation sample | `seed + (sha256(capture_id) mod 10000)` per capture, cap 4,000 flows |
| Outer capture folds | `StratifiedGroupKFold(shuffle=True, random_state=42)` on capture labels; the assignment is stored in `suite.json` |
| Inner selection folds | seed 43 (outer + 1) |
| Calibration folds for deployable models | seed 49 |
| Phase 10 validation-capture split | seed 53 (outer + 11) |
| Models | `random_state=42` (sklearn), `torch.manual_seed(42)` with deterministic algorithms (warn-only) |
| Bootstrap | `numpy.random.default_rng(42)`, 1,000 replicates |
| Phase 7 legacy split | `GroupShuffleSplit(test_size=0.2, random_state=42)` on `behavioral_hash` |

Re-running a suite creates a **new** suite id. Earlier results are never overwritten. Resuming with `--suite-id <existing>` skips experiments that are already COMPLETED or INFEASIBLE with the same config hash.

## 4. Where results live

| Artefact | Path |
|---|---|
| Append-only experiment index | `data/experiments/registry/index.jsonl` |
| Suite config, environment, dataset fingerprint, fold assignment | `data/experiments/phase{9,10}/<suite_id>/suite.json` |
| Suite summary (tables, paired contrasts) | `…/<suite_id>/summary.json` |
| Experiment record (config, metrics, bootstrap, coverage, costs, warnings, artefact checksums) | `…/<suite_id>/<experiment_id>/record.json` |
| Per-fold details (selected params, inner grid scores, calibration, thresholds, purge counts) | `…/<experiment_id>/folds.json` |
| Out-of-fold predictions | `…/<experiment_id>/predictions.parquet` (git-ignored, regenerable, SHA-256 in `record.json`) |
| Reports and claim ledger | `data/experiments/reports/` |
| Model registry | `data/model_registry/registry.json`; artefacts in `data/model_registry/artifacts/` (git-ignored) |

## 5. Verification

```bash
python -m pytest -q -p no:cacheprovider          # full backend / pipeline / ML suite
python -m ml verify                              # re-check every persisted result (see below)
cd frontend && npm ci && npm run build           # type-check + production build
```

* **The test suite does not need any git-ignored data.** The replay lifecycle tests use a labelled synthetic table, and a clean `git archive` export passes. Tests that exercise models use synthetic fixtures.
* **`python -m ml verify` re-checks the latest suites:**
  * it compares the SHA-256 of each experiment's `predictions.parquet` with its `record.json`;
  * it recomputes pooled AP, test FPR and recall at the validation threshold, and class counts, from the predictions (tolerance 1e-9);
  * it re-derives every claim status and compares it with `claim_ledger.json`.
* **The predictions are git-ignored.** On a fresh clone `verify` reports them as `MISSING` until the suites are re-run (§2), and a re-run creates new suite ids. On the integration branch, all 124 records were `VERIFIED` using the predictions produced by the original runs.
* **Model artefacts are git-ignored too.** On a fresh clone the registry lists ACTIVE models whose artefacts are absent. Inference then reports `LOAD_FAILED` and skips every flow (`NO_VALIDATED_MODEL`). Re-create the models with `python -m ml train-deployable` (§2).

## 6. Environment used for the recorded runs

Python 3.12.0, numpy 2.4.6, pandas 3.0.5, scikit-learn 1.9.0, scipy 1.18.0, pyarrow 25.0.1, dpkt 1.9.8, torch 2.13.0+cpu, Windows 11.
Each `suite.json` records the exact environment snapshot and git revision used for that run.

## 7. Sensor adapters (Phase 11)

The Zeek, Suricata and eBPF adapters are tested only against **synthetic fixtures** (`data/fixtures/sensors/`). The fixtures test software behaviour; they are not detection evidence.

```bash
python -m pytest -q -p no:cacheprovider tests/test_sensors_zeek.py tests/test_sensors_suricata.py \
    tests/test_sensors_ebpf.py tests/test_sensors_pipeline_integration.py tests/test_cross_phase_integration.py \
    tests/test_inference_contract.py tests/test_live_offline_parity.py tests/test_sensor_status_api.py
```

No native eBPF probe, Zeek process or Suricata process was run. See `docs/sensors/` and `docs/integration/CROSS_PHASE_CONTRACTS.md` for what the adapters guarantee.

## 8. Phase 7 pilot (historical)

The Phase 12 draft guide documented the Phase 7 pilot run. It is kept here for provenance only. The pilot is source-confounded and its metrics carry no information (see the claim ledger reconciliation).

```bash
python step7_step5_pilot_run.py   # writes data/experiments/phase7_step5_pilot/{pilot_fold_results.csv,pilot_summary.json}
```

The pilot used `GroupShuffleSplit(test_size=0.2, random_state=42)` on `behavioral_hash`, with preprocessing inside `imblearn` pipelines. Phase 9 replaced it with capture-grouped nested cross-validation (§3).
