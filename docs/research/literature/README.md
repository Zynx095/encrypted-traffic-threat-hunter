# ETTH Literature Review

This directory contains the structured literature review corpus for the Encrypted Traffic Threat Hunter (ETTH) research project.

## Purpose

The literature review establishes the theoretical and empirical foundation for ETTH's research question:

> Can JA4 TLS fingerprinting, combined with flow-level behavioral features and explainable ML, detect suspicious TLS-encrypted connections without decrypting payloads?

All findings recorded here must be traceable to their original sources. No findings are fabricated or inferred without explicit citation.

## Structure

```
literature/
├── README.md                           ← this file
├── corpus-manifest.csv                 ← master search record
├── literature-matrix.csv               ← structured extraction (22 columns)
├── annotated-bibliography/             ← per-source narrative summaries
│   └── README.md                       ← annotation guidelines
├── synthesis-notes.md                  ← cross-paper observations
├── section-01-encrypted-traffic-analysis.md
├── section-02-tls-fingerprinting.md
├── section-03-flow-based-nids.md
├── section-04-ml-methods.md
└── section-05-challenges-and-gaps.md
```

## Thematic Sections

1. **Encrypted Traffic Analysis Landscape** — feasibility, privacy framing, surveys, and taxonomies.
2. **TLS Fingerprinting: JA3 → JA4 → Future** — specification, limitations, ECH impact, and alternatives.
3. **Flow-Based Network Intrusion/Anomaly Detection** — features that survive encryption, C2 detection, obfuscation.
4. **ML Methods for Encrypted Traffic Classification** — supervised, deep learning, explainability, concept drift.
5. **Challenges, Gaps, and Positioning of ETTH** — synthesis, limitations, research gap statement, hypotheses.

## How to Add Papers

1. Search and screen sources using the search strategy in the literature review plan.
2. Record each candidate in `corpus-manifest.csv`.
3. For included sources, create a file in `annotated-bibliography/source-XXX.md` following the template in `annotated-bibliography/README.md`.
4. Add one row to `literature-matrix.csv` per included source.
5. Link the `citation_key` between the manifest, matrix, and bibliography.

## Maintaining the Literature Matrix

- Update `literature-matrix.csv` after reading each paper.
- Use the exact column schema defined in the review plan.
- Do not invent data. If a field is unknown, leave it blank.
- Use consistent terminology (e.g., JA4, ECH, CICIDS2017).

## Citation Conventions

- Citation keys follow the `surnameYYYYkeyword` pattern (e.g., `bock2018ja3`).
- All matrix rows reference a `citation_key` that must exist in the project's BibTeX file.
- Verify DOIs and URLs at time of entry.

## Research Gaps

Research gaps identified in this review are hypotheses until verified by the corpus. The timeline gate requires ≥40 sources in the matrix before narrative writing begins.
