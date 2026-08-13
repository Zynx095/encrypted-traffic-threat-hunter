# Annotated Bibliography Guidelines

Each source in `annotated-bibliography/` is documented as `source-XXX.md` where `XXX` is the zero-padded sequence number matching the `source_id` in `corpus-manifest.csv` and `id` in `literature-matrix.csv`.

## Template

```markdown
# [Full Title]

**Authors:** …  **Year:** …  **Venue:** …

## Citation
[formatted citation]
[DOI / URL]

## Problem Addressed

## Dataset

## Traffic Type / Protocol Scope

## Features Extracted

## Fingerprinting Method

## ML / Statistical Method

## Evaluation Metrics

## Main Findings

## Limitations

## Relevance to ETTH

## Notes & Caveats

## Potential Research Gap Contribution
```

## Instructions

- Replace the placeholder sections with concise, factual summaries.
- Base every claim on the source. Do not extrapolate beyond what the authors state.
- For datasets, specify version, capture conditions, and known biases if documented.
- For ML methods, include hyperparameter details only if they are central to reproducibility.
- Keep annotations to ~200 words per section.
- If a section does not apply, write "Not applicable" or "Not specified" rather than leaving it blank.
