# Encrypted Traffic Threat Hunter (ETTH)

> A research project developing machine-learning-based threat detection for encrypted network traffic using TLS metadata, JA4 fingerprinting, and flow-level behavioral features — without payload decryption.

## Research Purpose

The Encrypted Traffic Threat Hunter (ETTH) is a third-year engineering research project aimed at building a system capable of detecting threats and anomalous behavior in TLS-encrypted network traffic by analyzing only metadata-layer signals. The system eschews payload decryption entirely, relying on flow features, TLS handshake properties, and JA4/JA4S fingerprints to train and evaluate ML classifiers. This approach respects privacy and compliance boundaries while still enabling security-relevant inference.

**Current Status:** Research Foundation

## Architecture Overview

`
┌─────────────────────────────────────────────────────────────────────┐
│                          ETTH Architecture                          │
│                                                                     │
│  ┌────────────┐  ┌──────────┐  ┌──────────┐                        │
│  │   Zeek     │  │  TShark  │  │   JA4    │  (Flow & TLS metadata) │
│  └─────┬──────┘  └────┬─────┘  └────┬─────┘                        │
│        │              │            │                              │
│        └──────┬───────┴────────────┘                              │
│               │                                                     │
│         ┌─────▼─────┐     ┌──────────┐    ┌────────────┐          │
│         │  Parser    │────▶│  Feature  │───▶│  ML Engine  │         │
│         │   (FastAPI)│     │  Pipeline │    │ (MLflow)   │         │
│         └────────────┘     └─────┬─────┘    └──────┬─────┘         │
│                                   │                 │               │
│                         ┌─────────▼─────────┐       │              │
│                         │   PostgreSQL DB     │       │              │
│                         │  (Flow & Features) │       │              │
│                         └───────────────────┘       │              │
│                                                     │              │
│                          ┌────────────┐   ┌─────────▼──┐          │
│                          │  React UI   │◀──│  FastAPI   │          │
│                          │  (Frontend) │   │   API      │          │
│                          └────────────┘   └────────────┘          │
│                                                                     │
│                          ┌────────────────┐                       │
│                          │  Docker Compose│                       │
│                          │   (All-in-one) │                       │
│                          └────────────────┘                       │
└─────────────────────────────────────────────────────────────────────┘
`

### Major Technologies

| Layer            | Technology          | Purpose                                              |
|------------------|---------------------|------------------------------------------------------|
| Capture          | Zeek                | Passive network monitoring, flow generation          |
| Capture          | TShark              | Packet capture, dissection, TLS handshake parsing     |
| Fingerprinting   | JA4 / JA4S          | TLS client/server fingerprint strings                |
| Feature Engineering | Python (Pandas) | Transform flows into ML-ready feature vectors        |
| Machine Learning | Scikit-learn / XGBoost / PyTorch | Model training, evaluation, experiment tracking     |
| Experiment Tracking | MLflow          | Reproducible model experiments and versioning        |
| API              | FastAPI             | RESTful API for querying flows, features, predictions|
| Database         | PostgreSQL          | Persistent storage for flows, features, model metadata |
| Frontend         | React + TypeScript  | Dashboard for traffic overview, alerts, model status |
| Infrastructure   | Docker / Compose    | Containerized, reproducible deployment               |
| Testing          | Pytest              | Unit, integration, and reproducibility tests         |

## Critical Disclaimer

> **The ETTH system does NOT decrypt TLS payloads.**
>
> All analysis operates at the metadata layer only. The system inspects TLS handshake records, flow timing and size distributions, server name indication (SNI), certificate chain properties (subject, issuer, validity), cipher suites, extensions, and JA4/JA4S fingerprints. The plaintext of encrypted application data is never accessed, decoded, or reconstructed. This design ensures that privacy and regulatory boundaries are respected while still enabling threat detection through statistical and behavioral modeling.

## Directory Structure

`
etth/
├── docs/                          # Project documentation
│   ├── research/                  # Research notes, problem framing
│   ├── architecture/              # System architecture, diagrams
│   ├── decisions/                 # Architecture Decision Records (ADRs)
│   └── meeting-notes/             # Meeting minutes, sync notes
├── research/                      # Active research work
│   ├── literature/                # Annotated papers, reference corpus
│   ├── experiments/               # Experiment configs & runs (no results committed)
│   └── results/                   # Result artifacts & evaluation outputs
├── backend/                       # FastAPI application
├── frontend/                      # React dashboard
├── ml/                            # Machine learning pipeline
│   ├── notebooks/                 # Exploratory & analysis notebooks
│   ├── training/                  # Training scripts & pipelines
│   └── models/                    # Trained model artifacts (.gitignored)
├── network-analysis/              # Traffic ingestion & fingerprinting
│   ├── zeek/                      # Zeek scripts & configurations
│   ├── tshark/                    # TShark dissectors & extraction
│   └── ja4/                       # JA4/JA4S tooling & parsing
├── tests/                         # All test suites
├── data/                          # Data artifacts (.gitignored except fixtures)
│   └── fixtures/                  # Small, shared test fixtures
├── scripts/                       # Utility & orchestration scripts
├── paper/                         # Research paper & publication
│   ├── figures/                   # Figure source files
│   ├── tables/                    # Table source files
│   └── manuscript/                # LaTeX / markdown manuscript
├── docker/                        # Docker & Compose definitions
├── .gitignore                     # Ignore Python/Node/data/log artifacts
├── .env.example                   # Environment variable template
└── README.md                      # This file
`

## Core Research and Reproducibility Principles

1. **No payload inspection.** The system never reads or decrypts encrypted application data. Detection is based exclusively on observable metadata available without decryption.

2. **Reproducible experiments.** All model training, feature extraction, and evaluation runs are parameterized, version-controlled, and tracked through MLflow. Every experiment is defined by a declarative configuration committed to esearch/experiments/.

3. **Version-controlled artifacts.** Only small fixtures and notebooks are committed to git. Large datasets (PCAPs, flows), trained model binaries, and result artifacts generated during experiments are excluded via .gitignore and stored externally with version tracking at the data level.

4. **Separation of concerns.** Network capture, feature engineering, ML training, API serving, and UI are modularized into distinct directories, enabling independent development and evaluation of each layer.

5. **Transparent evaluation.** Results are reported with standard ML metrics (precision, recall, F1, ROC-AUC), confusion matrices, and ablation studies. No single metric tells the full story; all evaluation code is open within the repository.

6. **Privacy-first design.** By construction, no plaintext traffic content is ever persisted, logged, or processed. SNI and certificate metadata are treated according to the same retention rules as all flow data.
