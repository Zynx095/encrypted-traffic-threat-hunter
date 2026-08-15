# Encrypted Traffic Threat Hunter (ETTH)

> **Academic Research Project â€” Active Methodology and Pipeline Development**
>
> Investigating whether combining TLS fingerprint features (JA4, JA3, JA3S) with encrypted-flow
> behavioral features can improve malicious encrypted-traffic detection compared with either
> feature family alone â€” without decrypting payloads.

---

## Research Status

| Item | Status |
|---|---|
| Research status | ACTIVE â€” METHODOLOGY / PIPELINE DEVELOPMENT |
| Dataset strategy | MULTI-DATASET STRATEGY SELECTED |
| Current phase | Phase 6 â€” Data Ingestion and Preprocessing |
| Current completed step | Phase 6, Step 4 â€” Bidirectional Flow Reconstruction |
| ML model | NOT YET IMPLEMENTED |
| Real-time detection | NOT YET IMPLEMENTED |
| Research hypothesis | NOT YET TESTED |

---

## Research Objective

The ETTH project investigates whether a **feature-fusion approach** combining TLS handshake
fingerprints with bidirectional encrypted-flow behavioral statistics can improve threat detection
in modern TLS-encrypted network traffic compared with either family of features used independently.

The core hypothesis is evaluated through five experimental configurations:

| Config | Description | Status |
|---|---|---|
| **A** | Flow-only features | DESIGNED â€” NOT YET TRAINED |
| **B** | JA3-only fingerprint | DESIGNED â€” NOT YET TRAINED |
| **C** | JA4-only fingerprint | DESIGNED â€” NOT YET TRAINED |
| **D** | JA3 + Flow fusion | DESIGNED â€” NOT YET TRAINED |
| **E** | JA4 + Flow fusion | DESIGNED â€” NOT YET TRAINED |

These configurations have been formally specified in
[`docs/research/experimental-design.md`](docs/research/experimental-design.md).
No models have been trained and no results exist yet.

**The system never decrypts TLS payloads.** All analysis operates exclusively at
the metadata layer: TLS handshake records, flow timing, packet size distributions,
cipher suites, extensions, SNI, and fingerprint strings.

---

## Dataset Strategy

Phase 5 (Dataset Evaluation) is **CLOSED**. The final multi-dataset strategy is:

### Active Datasets

| ID | Name | Role | Access | TLS | PCAPs |
|---|---|---|---|---|---|
| DS-008 | [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/) | PRIMARY â€” Modern TLS Malware / C2 | Public download | TLS 1.2 + TLS 1.3 | Empirically verified |
| DS-004 | CipherSpectrum | MODERN TLS BENIGN VALIDATION | Sample access | TLS 1.3 (+ some TLS 1.0) | Empirically verified |

### Candidate Datasets â€” Pending Academic Access

| ID | Name | Role | Access |
|---|---|---|---|
| DS-006 | Beyond JA4+ | Potential primary with JA4 labels | ACADEMIC REQUEST REQUIRED â€” raw PCAPs restricted |
| DS-007 | Annotated Encrypted Network Traffic Dataset | Potential unified benchmark | ACADEMIC REQUEST REQUIRED â€” raw PCAPs restricted |

> **DS-006 and DS-007 are NOT currently part of the active processing pipeline.**
> Stub adapters exist in the codebase but no data has been ingested.

### Rejected / Secondary Datasets

| ID | Name | Reason for Rejection |
|---|---|---|
| DS-001 | ISCXVPN2016 | Legacy traffic; unsuitable as a primary modern-TLS / JA4 dataset |
| DS-002 | CIC-Darknet2020 | No raw PCAP availability for independent JA4 computation |
| DS-003 | USTC-TFC2016 | Empirically tested; available samples lacked usable modern TLS handshakes; SSL 3.0 predominant |
| DS-005 | CSTNET-TLS1.3 | Insufficient raw PCAP availability for independent JA4 extraction |
| DS-009 | Stratosphere MCFP | Not selected as primary; potential supplementary source |
| DS-010 | IoT-23 | Not selected as primary; potential cross-domain validation dataset |

### Critical Research Limitation

DS-004 (benign) and DS-008 (malware) originate from **different capture environments**:

- **DS-008** â€” Sandbox network; noisy, multi-flow, realistic adversarial conditions
- **DS-004** â€” Filtered enterprise-style captures; isolated single-flow extractions

This environmental disparity means dataset-source leakage is a **major ongoing research concern**.
Required controls include: IP/port/MAC removal, absolute timestamp stripping, relative timing
representation, careful feature normalization, and explicit dataset-source leakage analysis before
any model evaluation.

---

## Research Pipeline Architecture

```
Raw PCAPs
    â†“
Dataset Registry & SHA-256 Provenance          â† COMPLETE (Phase 6, Step 2)
    â†“
PCAP Integrity & Protocol Validation            â† COMPLETE (Phase 6, Step 3)
    â†“
Bidirectional Flow Reconstruction               â† COMPLETE (Phase 6, Step 4)  â—„ CURRENT
    â†“
TLS Handshake Extraction (JA3 / JA3S / JA4)    â† PENDING (Phase 6, Step 5)
    â†“
Encrypted Flow Features                         â† FUTURE
    â†“
Leakage-Controlled Model-Safe Dataset           â† FUTURE
    â†“
Experiments A â€“ E                               â† FUTURE
    â†“
Statistical Evaluation & Explainability         â† FUTURE
    â†“
Cross-Dataset / OOD Validation                  â† FUTURE
    â†“
Real-Time Threat-Hunting Prototype              â† FUTURE
```

### Data Tiering

The pipeline enforces a strict four-tier data architecture to prevent leakage:

```
RAW        â†’ Immutable original PCAPs (never modified, not committed to Git)
    â†“
INTERIM    â†’ Parsed flow records with full provenance metadata
    â†“
PROCESSED  â†’ Flow features with sensitive identifiers present
    â†“
MODEL-SAFE â†’ Sanitised features â€” no IPs, ports, MACs, or absolute timestamps
```

---

## Phase Progress

### Phase 5 â€” Dataset Evaluation and Selection â€” COMPLETE

All ten candidate datasets were evaluated across availability, TLS modernity,
raw PCAP access, JA4 feasibility, and labelling quality.
Final strategy and dataset roles are documented in
[`docs/research/final-dataset-strategy.md`](docs/research/final-dataset-strategy.md).

### Phase 6 â€” Data Ingestion and Preprocessing â€” IN PROGRESS

| Step | Title | Status |
|---|---|---|
| Step 1 | Ingestion Architecture Design | COMPLETE |
| Step 2 | Dataset Ingestion Foundation | COMPLETE |
| Step 3 | PCAP Integrity and Protocol Validation | COMPLETE |
| Step 4 | Deterministic Bidirectional Flow Reconstruction | **COMPLETE â€” CURRENT** |
| Step 5 | TLS Handshake Extraction and JA3 / JA3S / JA4 | PENDING |
| Step 6 | Encrypted Flow Feature Extraction | PENDING |
| Step 7 | Leakage-Controlled Model-Safe Dataset Construction | PENDING |
| Step 8 | Dataset-Source Leakage Analysis | PENDING |
| Step 9 | Phase 6 Integration and Validation | PENDING |

---

## Phase 6 Implementation Detail

### Step 2 â€” Dataset Ingestion Foundation

Implemented a modular Python ingestion package under `pipeline/`:

- **Primary parser:** `dpkt` (streaming, low-memory)
- **Fallback:** Scapy (stubbed)
- **Dataset adapters** (abstract base class + per-dataset implementations)
- **SHA-256 provenance** for every ingested PCAP
- **Manifest generation** in CSV and JSON for every ingestion run
- **PCAP format validation** (pcapng explicitly rejected; empty captures rejected)
- Unit tests for hashing, validation, and adapter metadata

**Active adapters:** DS-004, DS-008
**Stub adapters (no data):** DS-006, DS-007

### Step 3 â€” PCAP Integrity and Protocol Validation

Empirically characterised 8 verification-sample PCAPs (2 Ã— DS-008, 6 Ã— DS-004)
using streaming `dpkt` parsing without loading complete files into memory.

Key empirical findings:

| Finding | DS-008 | DS-004 |
|---|---|---|
| Parse errors | 0 | 0 |
| Malformed packets | 0 | 0 |
| TLS detected (structural) | âœ“ | âœ“ |
| ClientHello present | âœ“ | âœ“ |
| ServerHello present | âœ“ | âœ“ |
| TLS 1.3 (via supported_versions) | âœ“ | âœ“ (4 of 6 samples) |
| TLS 1.2 | âœ“ | âœ— |
| TLS 1.0 | âœ— | âœ“ (2 of 6 samples) |
| Traffic profile | Multi-flow, noisy | Isolated single-flow |

> These 8 PCAPs are **verification samples only**, not the complete datasets.
> TLS was detected structurally via payload inspection â€” not by assuming port 443 = TLS.
> TLS 1.3 was identified using the `supported_versions` extension, not the legacy
> `0x0303` record-layer version field.

### Step 4 â€” Deterministic Bidirectional Flow Reconstruction

Implemented in `pipeline/flow_reconstruction.py`.

**Canonical flow key:** `(min(ep_src, ep_dst), max(ep_src, ep_dst), protocol)` â€” direction-agnostic.

**Direction assignment:** The first observed packet's source endpoint becomes `FORWARD`;
the counterpart endpoint becomes `REVERSE`. No assumption of client vs. server role is made
from port numbers or IP space alone.

**Flow IDs:** SHA-256 hash of `{PCAP_SHA256}_{canonical_key}_{instance_index}`.
Deterministic: reprocessing the same PCAP produces identical IDs.

**Flow instance separation:**
- Configurable idle timeout: **120 seconds** *(DEFAULT_CONFIGURATION â€” `PENDING_PILOT_VALIDATION`)*
- TCP FIN or RST terminates the current instance; subsequent packets on the same 5-tuple open a new instance.
- UDP relies on idle timeout only (no termination flags available).

**Per-flow statistics preserved:**
`packet_count`, `forward/reverse_packet_count`, `byte_count`, `forward/reverse_byte_count`,
`packet_lengths`, `direction_sequence`, `relative_times`, `tcp_flags`, `tls_candidate_sequence`

**Invariants tested and verified:**
- Forward packets + reverse packets = total packets
- Forward bytes + reverse bytes = total bytes
- Packet count = length of all sequence arrays
- Flow start â‰¤ flow end; all relative times â‰¥ 0

**Empirical reconstruction results on verification samples:**

| Dataset | PCAP | Flows reconstructed |
|---|---|---|
| DS-004 | sample1â€“6 (6 PCAPs) | 1 flow each |
| DS-008 | AsyncRAT+XWorm capture | 74 flows |
| DS-008 | XLoader capture | 1,380 flows |

Outputs written to `data/interim/flows/` as Parquet files.

---

## Repository Structure

```
encrypted-traffic-threat-hunter/
â”œâ”€â”€ docs/
â”‚   â””â”€â”€ research/                  # Research documentation (Phase 5 + Phase 6 reports)
â”‚       â”œâ”€â”€ dataset-registry.md
â”‚       â”œâ”€â”€ experimental-design.md
â”‚       â”œâ”€â”€ final-dataset-strategy.md
â”‚       â”œâ”€â”€ phase-6-ingestion-architecture.md
â”‚       â”œâ”€â”€ phase-6-step-2-ingestion.md
â”‚       â”œâ”€â”€ phase-6-step-3-pcap-validation.md
â”‚       â””â”€â”€ phase-6-step-4-flow-reconstruction.md
â”œâ”€â”€ pipeline/                      # Phase 6 ingestion and preprocessing
â”‚   â”œâ”€â”€ adapters/                  # Per-dataset adapters (DS-004, DS-008, DS-006 stub, DS-007 stub)
â”‚   â”œâ”€â”€ config.py                  # Relative-path pipeline configuration
â”‚   â”œâ”€â”€ hashing.py                 # SHA-256 provenance
â”‚   â”œâ”€â”€ pcap_validator.py          # PCAP format and integrity validation
â”‚   â”œâ”€â”€ ingestion.py               # Ingestion orchestrator
â”‚   â”œâ”€â”€ manifest.py                # CSV/JSON manifest generation
â”‚   â””â”€â”€ flow_reconstruction.py     # Bidirectional flow reconstruction engine
â”œâ”€â”€ tests/
â”‚   â”œâ”€â”€ test_ingestion.py          # Ingestion and adapter unit tests
â”‚   â”œâ”€â”€ test_step3_validation.py   # Protocol detection unit tests
â”‚   â””â”€â”€ test_flow_reconstruction.py# Flow reconstruction invariant tests
â”œâ”€â”€ data/
â”‚   â”œâ”€â”€ raw/                       # Immutable PCAPs (not committed to Git)
â”‚   â”œâ”€â”€ samples/                   # Verification sample PCAPs (small, not committed)
â”‚   â”œâ”€â”€ interim/flows/             # Reconstructed flow Parquet files
â”‚   â”œâ”€â”€ manifests/                 # Ingestion manifests (CSV + JSON)
â”‚   â””â”€â”€ verification/results/      # Step 3 protocol validation outputs
â”œâ”€â”€ research/                      # Literature, experiment configs, result artifacts
â”œâ”€â”€ backend/                       # FastAPI stub (not yet active)
â”œâ”€â”€ frontend/                      # React dashboard stub (not yet active)
â”œâ”€â”€ ml/                            # ML pipeline (not yet active)
â”œâ”€â”€ paper/                         # Manuscript preparation
â””â”€â”€ step3_analysis.py              # Phase 6 Step 3 standalone analysis runner
    step4_run.py                   # Phase 6 Step 4 standalone flow reconstruction runner
```

---

## Data Safety

- **Raw PCAPs are excluded from Git tracking** via `.gitignore`. They are treated as external research artifacts.
- **Malware PCAPs are never executed.** The `dpkt` parser reads only packet envelopes passively; application-layer payloads are not extracted, interpreted, or forwarded to any system.
- The repository stores code, metadata, manifests, verification results, and documentation â€” not malware payloads.
- Sensitive identifiers (IPs, ports, MACs, absolute timestamps) will be removed from MODEL-SAFE outputs before any model training occurs.

---

## Future Roadmap

| Phase | Title | Status |
|---|---|---|
| Phase 6 | Data Ingestion and Preprocessing | IN PROGRESS |
| Phase 7 | Feature Extraction and Experimental Dataset Construction | FUTURE |
| Phase 8 | Model Development and Baseline Experiments | FUTURE |
| Phase 9 | Statistical Evaluation and Explainability | FUTURE |
| Phase 10 | Cross-Dataset / Out-of-Distribution Validation | FUTURE |
| Phase 11 | Real-Time Encrypted Traffic Threat-Hunting Prototype | FUTURE |
| Phase 12 | Research Evaluation, Paper Preparation, and Final Documentation | FUTURE |

---

## Research Principles

1. **No payload decryption.** The system never reads or reconstructs encrypted application data.
   Detection relies exclusively on observable metadata available without breaking TLS.

2. **Empirical verification over assumption.** Every dataset property claimed in this project
   has been empirically verified from actual PCAP samples. Unverified claims are explicitly
   labelled `NOT_VERIFIED` or `PENDING_PILOT_VALIDATION`.

3. **Deterministic and reproducible.** Flow IDs, manifests, and validation outputs are
   deterministically reproducible from the same inputs. No randomness is introduced in
   provenance-critical code paths.

4. **Leakage-controlled evaluation.** The four-tier data architecture (RAW â†’ INTERIM â†’
   PROCESSED â†’ MODEL-SAFE) explicitly prevents sensitive identifiers from influencing model
   training. Dataset-source leakage will be formally analysed before any experimental evaluation.

5. **Explicit uncertainty.** Open scientific decisions â€” including the final flow idle timeout,
   primary packet-length representation, retransmission handling, and TLS session segmentation â€”
   are documented as `PENDING_PILOT_VALIDATION` rather than silently assumed.

6. **Version-controlled documentation.** All architectural decisions, dataset evaluations,
   and phase results are documented in `docs/research/` and committed to the repository alongside
   the code they describe.

---

## Related Documentation

| Document | Contents |
|---|---|
| [`docs/research/research-plan.md`](docs/research/research-plan.md) | Full multi-phase research plan |
| [`docs/research/experimental-design.md`](docs/research/experimental-design.md) | Experiments Aâ€“E, metrics, and statistical test plan |
| [`docs/research/final-dataset-strategy.md`](docs/research/final-dataset-strategy.md) | Phase 5 final dataset decision |
| [`docs/research/phase-6-ingestion-architecture.md`](docs/research/phase-6-ingestion-architecture.md) | Step 1 architecture specification |
| [`docs/research/phase-6-step-4-flow-reconstruction.md`](docs/research/phase-6-step-4-flow-reconstruction.md) | Step 4 design decisions and open questions |
