"""
ETTH research ML package (Phases 9 and 10).

Subpackages:
    features    -- feature governance registry, track schemas, leakage guard
    estimators  -- exportable preprocessing, model zoo, safe model artefacts
    evaluation  -- split protocols, metric conventions, group-aware uncertainty
    benchmark   -- experiment runner and immutable experiment registry
    diagnostics -- coverage, shortcut probes, source identifiability
    sequence    -- Phase 10 sequence datasets, models and training
    reporting   -- claim ledger and report generation

The directory is deliberately not called `models/`: the repository .gitignore ignores every
directory with that name.
"""
