# ETTH Phase 5 Master Audit

## 1. Audit Date
2026-08-14

## 2. Repository State
The repository contains the core Phase 5 research foundation documents, dataset evaluation records, and experimental design. The scientific integrity of the documentation is high, properly preserving uncertainty and tracking dataset limitations. However, some Phase 5 files are currently untracked, one required quality control report is entirely missing, and a parallel worktree exists which could lead to confusion. 

## 3. Git State
- **Current Branch:** `main` (up to date with `origin/main`)
- **Cleanliness:** `main` is NOT completely clean. There are 6 untracked files.
- **Untracked Files:** 
  - `docs/research/dataset-discovery-report.md`
  - `docs/research/dataset-selection-scorecard.md`
  - `docs/research/dataset-verification-queue.md`
  - `fix_csv.py`
  - `fix_csv2.py`
  - `fix_registry.py`
- **Worktrees:** A secondary worktree exists at `.kilo/worktrees/sage-albatross`.
- **Accidental Branches:** The branch `sage-albatross` exists.

## 4. Phase 5 Files

| File | Exists in Main | Valid | Notes |
|------|----------------|-------|-------|
| `dataset-evaluation.md` | Yes | Yes | |
| `dataset-acceptance-criteria.md` | Yes | Yes | |
| `dataset-registry.csv` | Yes | Yes | Valid structure, 38 columns, 5 datasets. |
| `dataset-registry.md` | Yes | Yes | |
| `dataset-registry-quality-report.md` | **NOT PRESENT IN MAIN** | No | File is completely missing from the repository. |
| `dataset-selection-scorecard.md` | Yes (Untracked) | Yes | Must be added to git. |
| `dataset-verification-queue.md` | Yes (Untracked) | Yes | Must be added to git. |
| `research-problem.md` | Yes | Yes | |
| `experimental-variables.md` | Yes | Yes | |
| `experimental-design.md` | Yes | Yes | |
| `research-design-summary.md` | Yes | Yes | |
| `research-foundation.md` | Yes | Yes | |
| `literature/` | Yes | Yes | Directory exists. |
| `research-plan.md` | Yes | Yes | Contains a typo in the filename. |
| `dataset-discovery-report.md` | Yes (Untracked) | Yes | Supplemental file, untracked. |

## 5. Dataset Registry Audit
The dataset registry (`dataset-registry.csv` and `dataset-registry.md`) is correctly structured.
- Contains 5 dataset entries.
- No duplicate dataset IDs or names.
- Columns are correctly formatted.
- Uncertainty is properly preserved (no unsupported claims of JA4 computability; heavily uses `NOT_VERIFIED`, `PENDING`, and `PARTIALLY_VERIFIED`).
- The markdown documentation aligns with the CSV data.

## 6. Dataset Quality-Control Audit
**FAILED.** The required `dataset-registry-quality-report.md` does not exist in `main` or the `sage-albatross` worktree. We cannot verify whether the automated or structured checks for schema consistency, duplicate datasets, and evidence completeness were properly reported.

## 7. Dataset Selection Audit
**PASSED.** The `dataset-selection-scorecard.md` accurately weights criteria:
- Raw PCAP, ClientHello, ServerHello, and JA4 computability are mandatory. 
- Dataset size is explicitly capped at 1.0 weight to prevent large, noisy datasets from dominating.
- It does not treat "TLS traffic exists" as equivalent to "JA4 is computable" (properly leaving JA4 as `NOT_VERIFIED` for the datasets).

## 8. Experiment Mapping Audit
**PASSED.** The experimental design defines 5 configurations (A-E). The scorecard correctly maps them, identifying that JA3/JA4 experiments (B-E) are `NOT_SUPPORTED` for CSV-only datasets like CIC-Darknet2020, and `PENDING_VERIFICATION` for PCAP datasets until ClientHello presence is confirmed.

## 9. Research Question Consistency
**PASSED.** All documents consistently focus on the central ETTH research question: combining TLS fingerprint features (JA4/JA3S) with encrypted-flow behavioral features. There is no silent pivot to generic malware classification or DPI.

## 10. Research Design Consistency
**PASSED.** No scientific contradictions were found. All documents consistently identify USTC-TFC2016 as a provisional primary dataset, note its limitations (legacy TLS, high unencrypted volume), and appropriately leave JA4 computability as unverified until manual checks are done.

## 11. Leakage Risk Audit
**PASSED.** The scorecard identifies crucial leakage risks: SNI leakage, IP/Port leakage, Timestamp/flow ID leakage, capture-environment leakage, malware-family memorization, duplicate-flow contamination, and dataset-source classification. Mitigations are documented.

## 12. Modern TLS/ECH Audit
**PASSED.** The research correctly distinguishes between TLS 1.2, TLS 1.3, and QUIC. It explicitly calls out that current candidate datasets (ISCXVPN2016, USTC-TFC2016) heavily rely on deprecated ciphers and legacy TLS, identifying the need for a modern TLS 1.3 validation dataset.

## 13. Dataset Strategy
**PASSED.** The project correctly identifies that a final primary dataset has NOT been selected. The status is accurately described as provisional/pending verification, acknowledging that empirical testing is required before final commitment.

## 14. Research Novelty Check
**PASSED.** The novelty claim correctly focuses on feature fusion, explainability (via SHAP) for hybrid models, and behavior under ECH conditions, rather than outdated claims like "comparing JA4 and flow stats".

## 15. Scientific Readiness
**READY WITH CONDITIONS**
The scientific foundation is extremely strong and rigorous. However, administrative repository cleanup and the generation of one missing report are required before moving to Phase 6.

## 16. Problems Found

**CRITICAL**
- `docs/research/dataset-registry-quality-report.md` is missing.

**HIGH**
- `docs/research/dataset-selection-scorecard.md` and `docs/research/dataset-verification-queue.md` are untracked.
- Split-brain repository state: the `sage-albatross` worktree and branch exist and might cause confusion.

**MEDIUM**
- **MEDIUM**
- Temporary python scripts (fix_csv.py, etc.) have been removed.

**LOW**
- Typo in filename: `research-plan.md` instead of `research-plan.md`.

## 17. Required Corrections
1. Track and commit the untracked Phase 5 markdown files in `main`.
2. Generate and commit the missing `dataset-registry-quality-report.md`.
3. Rename `research-plan.md` to `research-plan.md`.
4. Delete or `.gitignore` the temporary python fix scripts.
5. Remove the `sage-albatross` worktree to ensure `main` is the unquestioned source of truth.

## 18. Items That Must Be Verified Manually
- Download sample PCAPs from USTC-TFC2016 and ISCXVPN2016 to verify TLS ClientHello/ServerHello presence.
- Run JA3/JA4 extraction tools on the sample PCAPs.
- Compute exact encrypted-flow class balances after filtering out the unencrypted traffic.
- Request/verify access to modern TLS 1.3 datasets (CipherSpectrum or CSTNET-TLS1.3).

## 19. Phase 5 Final Verdict
**READY WITH CONDITIONS**

## 20. Recommended Next Phase
Phase 6 should focus strictly on **Empirical Dataset Verification and Pipeline Initialization**. This means downloading sample PCAPs, executing the verification queue to test JA4 extraction and flow filtering, finalizing the dataset selection based on empirical results, and setting up the foundational data ingestion pipeline.
