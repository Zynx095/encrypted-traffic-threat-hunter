# Repository Unused File Inventory

**Date:** 2026-08-16
**Purpose:** Document all files that appear unused or potentially obsolete, with classifications and recommended actions.

## File Inventory

| Path | Classification | Last Known Purpose | Current References | Current Execution Status | Reproducible? | Historical? | Future Value | Deletion Safety | Recommended Action |
|------|----------------|-------------------|--------------------|--------------------------|---------------|-------------|--------------|-----------------|-------------------|
| step65_step4_run.py | F — FUTURE_USE | Stage 6.5 pipeline execution script | Referenced in phase-6.5-step-4-expanded-pipeline-rebuild.md | Not executed (one-off) | Yes (pipeline modules) | Yes | Template for future re-execution | UNSAFE | KEEP |
| docs/research/mta-corpus-candidate-registry.csv | C — HISTORICAL_RESEARCH | MTA corpus candidate tracking | Referenced in phase-6.5-step-1-mta-discovery.md | Not executed | Yes | Yes | Historical record | UNSAFE | KEEP |

## Summary
- **Total files inspected:** 2 potentially unused files
- **Files safe to delete:** 0 (both have historical/future value)
- **Files requiring human review:** 0
- **Files to retain:** All other files in repository

## Deletion Justification
The fix_csv*.py files were already deleted during the cleanup phase. The remaining files (step65_step4_run.py and mta-corpus-candidate-registry.csv) are:
1. Not imported by any active code
2. Not executed as part of any pipeline
3. Not safe to delete because they have historical/future value:
   - step65_step4_run.py: One-off execution script for Stage 6.5 rebuild; needed if pipeline must be re-run
   - mta-corpus-candidate-registry.csv: Historical record of MTA corpus candidate evaluation
Their removal would degrade reproducibility and historical record without benefit.