# Research Claim Ledger

The ledger is **generated**, not hand-written. Each claim is evaluated by a fixed rule in `ml/reporting/claims.py` against persisted artefacts: corpus reports, suite summaries, experiment records and tests.

* Live version: `data/experiments/reports/claim_ledger.json` (also served at `GET /api/research/claims` and shown in the Research Workbench, Claims tab).
* Regenerate: `python -m ml report`

## Status vocabulary and rules

| Status | Meaning in this project |
|---|---|
| SUPPORTED | Directly verified (deterministic rebuild, descriptive corpus facts, engineering properties under test). |
| PRELIMINARY | Exploratory evidence in the claimed direction. **This is the ceiling for any detection-performance claim on the current corpus**, because each dataset contributes a single class. |
| CONTRADICTED | Exploratory evidence against the claim (e.g. a paired CI entirely on the wrong side, Holm-significant). |
| INSUFFICIENT_EVIDENCE | No defensible conclusion. A non-significant or unstable difference falls here; it is never read as "no effect". |
| UNTESTED | The producing experiment has not completed. |
| BLOCKED | A prerequisite (independent data, confirmatory source) is unavailable. |

Every claim record carries: claim text, supporting experiment IDs, datasets, protocol, metrics, uncertainty, assumptions, known confounders and limitations.

## Snapshot

The table below is copied verbatim from the last generated `claim_ledger.json` (see the generation timestamp in the final report).
