# Phase 6 Ingestion Architecture

## 1. Purpose

This document defines the complete architecture for the ETTH Phase 6 Data Ingestion and Preprocessing Pipeline. The pipeline transforms raw PCAP files from heterogeneous dataset sources into a single, validated, flow-level research dataset suitable for Phase 7 feature engineering and Phase 8+ ML experimentation.

The pipeline must be:
- **Dataset-agnostic:** A common core that processes any PCAP, with thin dataset-specific adapters for label and metadata ingestion only.
- **Reproducible:** Deterministic outputs given identical inputs and configuration.
- **Auditable:** Every processed record traceable to its source PCAP, packet offsets, and pipeline version.
- **Leakage-aware:** Raw identifiers preserved for debugging but explicitly excluded from model-eligible outputs.

---

## 2. Inputs

| Input | Source | Format | Status |
|-------|--------|--------|--------|
| DS-008 malware PCAPs | malware-traffic-analysis.net | `.pcap` in password-protected `.zip` | VERIFIED_YES (2 samples extracted) |
| DS-004 benign PCAPs | cspectrum.web.cse.unsw.edu.au | `.pcap` in `.zip` | VERIFIED_YES (6 samples available) |
| DS-008 labels | MTA blog post metadata (date, family, IOCs) | Manual text / structured metadata | Per-PCAP manual curation |
| DS-004 labels | CipherSpectrum dataset metadata | CSV / directory structure | Per-session labels |
| Future DS-006/DS-007 PCAPs | Academic access (Brno University) | `.pcap` (expected) | PENDING |

---

## 3. Outputs

The pipeline produces three output tiers:

| Tier | Directory | Contents | Git-tracked |
|------|-----------|----------|-------------|
| **INTERIM** | `data/interim/` | Per-PCAP flow records with all fields including raw IPs, ports, timestamps. Parquet format. | NO |
| **PROCESSED** | `data/processed/` | Merged, deduplicated, quality-checked flow records. Full provenance. Parquet format. | NO |
| **MODEL-SAFE** | `data/processed/model_safe/` | Feature matrix with leakage-prone fields stripped. Parquet format. Ready for Phase 7. | NO |

The final **Phase 7 handoff** is the MODEL-SAFE tier.

---

## 4. Pipeline Overview

```
RAW PCAP (immutable)
    â”‚
    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  1. PCAP Discovery      â”‚  Scan data/raw/{dataset_id}/ for .pcap files
â”‚     & Registration      â”‚  Compute SHA-256 checksums
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  2. PCAP Validation     â”‚  Verify magic bytes, readability, packet count > 0
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  3. Packet Parsing      â”‚  dpkt: Ethernet â†’ IP â†’ TCP/UDP â†’ payload
â”‚     & TLS Detection     â”‚  Identify TLS record type 22 (Handshake)
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  4. Flow Reconstruction â”‚  Bidirectional 5-tuple grouping
â”‚                         â”‚  Configurable idle timeout
â”‚                         â”‚  Packet-level metadata capture
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  5. TLS Session         â”‚  ClientHello detection & metadata extraction
â”‚     Identification      â”‚  ServerHello detection & metadata extraction
â”‚                         â”‚  TLS version determination
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  6. Flow-Level Feature  â”‚  Packet counts, byte counts, durations
â”‚     Summarization       â”‚  Packet-length sequences, IAT sequences
â”‚                         â”‚  Direction ratios
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  7. Label Ingestion     â”‚  Dataset adapter loads original labels
â”‚     (Dataset Adapter)   â”‚  Maps to normalized schema
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  8. Provenance &        â”‚  Attach dataset_id, source_file, checksums,
â”‚     Metadata Tagging    â”‚  pipeline version, extraction timestamp
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  9. Quality Control     â”‚  Schema validation, null checks, TLS sanity,
â”‚                         â”‚  flow duration bounds, duplicate detection
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ 10. INTERIM Output      â”‚  Write per-PCAP Parquet to data/interim/
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ 11. Merge & Dedup       â”‚  Concatenate all interim files
â”‚                         â”‚  Cross-file duplicate detection
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ 12. Leakage Control     â”‚  Generate MODEL-SAFE view:
â”‚                         â”‚  Strip IP, Port, MAC, abs timestamps, SNI text
â”‚                         â”‚  Retain only behavioral & TLS structural fields
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚
          â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ 13. PROCESSED &         â”‚  Write final Parquet files
â”‚     MODEL-SAFE Output   â”‚  Write processing manifest & logs
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

---

## 5. Directory Structure

The existing repository structure will be extended as follows. Directories marked `[GITIGNORED]` are already excluded by `.gitignore` or will be added.

```
data/
â”œâ”€â”€ raw/                          [GITIGNORED] Immutable source PCAPs
â”‚   â”œâ”€â”€ ds004/                    CipherSpectrum PCAPs
â”‚   â”œâ”€â”€ ds008/                    MTA malware PCAPs
â”‚   â”œâ”€â”€ ds006/                    (Future) Beyond JA4+ PCAPs
â”‚   â””â”€â”€ ds007/                    (Future) Annotated Encrypted Traffic PCAPs
â”‚
â”œâ”€â”€ samples/                      [GITIGNORED] Small verification samples (existing)
â”‚   â”œâ”€â”€ ds003/
â”‚   â””â”€â”€ ds004/
â”‚
â”œâ”€â”€ interim/                      [GITIGNORED] Per-PCAP extracted flow records
â”‚   â”œâ”€â”€ ds004/
â”‚   â””â”€â”€ ds008/
â”‚
â”œâ”€â”€ processed/                    [GITIGNORED] Merged, validated flow dataset
â”‚   â”œâ”€â”€ flows.parquet             Full provenance dataset
â”‚   â”œâ”€â”€ model_safe/
â”‚   â”‚   â””â”€â”€ flows_model_safe.parquet  Leakage-controlled feature matrix
â”‚   â””â”€â”€ manifests/
â”‚       â””â”€â”€ processing_manifest.json
â”‚
â”œâ”€â”€ verification/                 Existing verification scripts & results
â”‚   â”œâ”€â”€ verify_ds003.py
â”‚   â”œâ”€â”€ verify_ds004.py
â”‚   â”œâ”€â”€ verify_ds008.py
â”‚   â”œâ”€â”€ output/
â”‚   â”œâ”€â”€ pcaps/                    [GITIGNORED]
â”‚   â””â”€â”€ results/
â”‚
â””â”€â”€ fixtures/                     Test fixtures (.gitkeep)

pipeline/                         [NEW] Phase 6 pipeline code
â”œâ”€â”€ __init__.py
â”œâ”€â”€ config.py                     Pipeline configuration & constants
â”œâ”€â”€ cli.py                        Command-line entry point
â”œâ”€â”€ pcap_discovery.py             PCAP scanning & checksum computation
â”œâ”€â”€ pcap_validator.py             PCAP integrity checks
â”œâ”€â”€ packet_parser.py              dpkt-based packet parsing
â”œâ”€â”€ tls_parser.py                 TLS handshake detection & metadata extraction
â”œâ”€â”€ flow_reconstructor.py         Bidirectional flow reconstruction
â”œâ”€â”€ flow_features.py              Flow-level statistical summarization
â”œâ”€â”€ leakage_control.py            Model-safe view generation
â”œâ”€â”€ quality_control.py            Schema validation & sanity checks
â”œâ”€â”€ provenance.py                 Provenance tagging & manifest generation
â”œâ”€â”€ schema.py                     Canonical flow schema definition
â”œâ”€â”€ adapters/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ base.py                   Abstract dataset adapter interface
â”‚   â”œâ”€â”€ ds004_adapter.py          CipherSpectrum label & metadata adapter
â”‚   â””â”€â”€ ds008_adapter.py          MTA label & metadata adapter
â””â”€â”€ utils.py                      Shared utilities (hashing, logging)
```

---

## 6. Dataset Adapters

Each dataset requires a thin adapter to handle dataset-specific concerns. The adapters share a common interface defined in `adapters/base.py`.

### 6.1 Adapter Interface

```python
class DatasetAdapter:
    dataset_id: str                    # e.g., "DS-008"
    dataset_name: str                  # e.g., "Malware-Traffic-Analysis.net"

    def get_pcap_paths(self) -> list   # Return list of PCAP file paths
    def get_label(self, pcap_path, flow_key) -> dict
        # Returns: {
        #   "label_original": str,     # e.g., "XLoader"
        #   "label_normalized": str,   # e.g., "MALICIOUS"
        #   "label_source": str,       # e.g., "mta_blog_metadata"
        #   "label_confidence": str,   # e.g., "HIGH"
        #   "malware_family": str,     # e.g., "XLoader" or "UNKNOWN"
        # }
    def get_capture_metadata(self, pcap_path) -> dict
        # Returns: {
        #   "capture_date": str,
        #   "capture_environment": str,
        #   "capture_source": str,
        # }
```

### 6.2 DS-008 Adapter (MTA)

- **PCAP discovery:** Scans `data/raw/ds008/` for `.pcap` files.
- **Label extraction:** Parses the PCAP filename convention (`YYYY-MM-DD-{family}-infection-traffic.pcap`) to extract `capture_date` and `malware_family`.
- **Label normalization:** All DS-008 traffic is labeled `MALICIOUS` with `label_source = "mta_filename_convention"`.
- **Capture metadata:** `capture_environment = "SANDBOX"`, derived from MTA blog documentation.
- **Special handling:** MTA PCAPs contain mixed traffic (DNS, HTTP, TLS). The pipeline filters to TLS flows only during flow reconstruction; non-TLS flows are tagged but excluded from the primary research dataset.

### 6.3 DS-004 Adapter (CipherSpectrum)

- **PCAP discovery:** Scans `data/raw/ds004/` for `.pcap` files.
- **Label extraction:** CipherSpectrum labels are derived from the dataset's published metadata (application categories, session types). Since CipherSpectrum contains no malware, all traffic is labeled with its original application-level label.
- **Label normalization:** `label_normalized = "BENIGN_VALIDATION"`. This is deliberately NOT `BENIGN` to signal that the benign designation is inferred from the absence of malware in the dataset, not from explicit benign ground truth.
- **Capture metadata:** `capture_environment = "ENTERPRISE_NETWORK"`, per the CipherSpectrum documentation.

### 6.4 Future Adapters (DS-006, DS-007)

Stub adapters will be created with `NOT_IMPLEMENTED` methods. They will be completed when/if academic PCAP access is granted. The common schema ensures they will slot in without pipeline redesign.

---

## 7. Canonical Flow Schema

Every flow record produced by the pipeline conforms to this schema. Fields are categorized into three access tiers.

### 7.1 Provenance Fields (PROVENANCE tier â€” never used in ML)

| Field | Type | Description |
|-------|------|-------------|
| `dataset_id` | string | Source dataset identifier (e.g., `DS-008`) |
| `source_file` | string | Original PCAP filename |
| `source_file_sha256` | string | SHA-256 of the source PCAP |
| `flow_id` | string | Deterministic flow identifier (hash of 5-tuple + start time) |
| `pipeline_version` | string | Semantic version of the extraction pipeline |
| `extraction_timestamp` | string | ISO-8601 timestamp of when this record was created |

### 7.2 Raw Fields (RAW tier â€” retained for debugging/audit, excluded from ML)

| Field | Type | Description |
|-------|------|-------------|
| `src_ip` | string | Source IP address |
| `dst_ip` | string | Destination IP address |
| `src_port` | uint16 | Source port |
| `dst_port` | uint16 | Destination port |
| `protocol` | uint8 | IP protocol number (6=TCP, 17=UDP) |
| `timestamp_start` | float64 | Absolute epoch timestamp of first packet |
| `timestamp_end` | float64 | Absolute epoch timestamp of last packet |
| `sni_value` | string | SNI domain if present, else empty string |
| `capture_source` | string | Capture environment identifier |

### 7.3 Model-Eligible Fields (MODEL_SAFE tier â€” available for Phase 7 feature engineering)

| Field | Type | Description |
|-------|------|-------------|
| `duration` | float64 | Flow duration in seconds (`timestamp_end - timestamp_start`) |
| `packet_count` | uint32 | Total packet count |
| `forward_packet_count` | uint32 | Packets from initiator â†’ responder |
| `reverse_packet_count` | uint32 | Packets from responder â†’ initiator |
| `byte_count` | uint64 | Total bytes |
| `forward_byte_count` | uint64 | Bytes initiator â†’ responder |
| `reverse_byte_count` | uint64 | Bytes responder â†’ initiator |
| `packet_lengths` | list[uint16] | Ordered sequence of all packet payload lengths |
| `forward_packet_lengths` | list[uint16] | Payload lengths (initiator â†’ responder) |
| `reverse_packet_lengths` | list[uint16] | Payload lengths (responder â†’ initiator) |
| `iat_sequence` | list[float64] | Inter-arrival times (seconds) between consecutive packets |
| `forward_iat_sequence` | list[float64] | IATs for forward packets only |
| `reverse_iat_sequence` | list[float64] | IATs for reverse packets only |
| `tls_detected` | bool | Whether any TLS record was observed |
| `tls_version` | string | Negotiated TLS version (e.g., `"1.3"`, `"1.2"`, `"unknown"`) |
| `clienthello_present` | bool | Whether a ClientHello was observed |
| `serverhello_present` | bool | Whether a ServerHello was observed |
| `sni_present` | bool | Whether SNI was present in ClientHello (boolean only, NOT the domain) |
| `alpn_first` | string | First ALPN protocol string (e.g., `"h2"`, `"http/1.1"`) or empty |
| `cipher_suite_count` | uint16 | Number of non-GREASE cipher suites in ClientHello |
| `extension_count` | uint16 | Number of non-GREASE extensions in ClientHello |
| `supported_versions_present` | bool | Whether `supported_versions` extension exists (TLS 1.3 indicator) |
| `label_original` | string | Original dataset-provided label |
| `label_normalized` | string | Normalized binary label: `MALICIOUS` or `BENIGN_VALIDATION` |
| `label_source` | string | How the label was determined |
| `label_confidence` | string | `HIGH`, `MEDIUM`, `LOW` |
| `malware_family` | string | Malware family if known, else `UNKNOWN` |

> **Design Note on SNI:** The `sni_value` (actual domain string) is stored in the RAW tier for audit purposes only. The MODEL_SAFE tier contains only `sni_present` (boolean). This prevents the model from memorizing domain names while preserving the signal that an SNI extension was offered.

---

## 8. Raw vs Intermediate vs Model-Safe Data

| Property | RAW | INTERIM | PROCESSED | MODEL-SAFE |
|----------|-----|---------|-----------|------------|
| Location | `data/raw/` | `data/interim/` | `data/processed/` | `data/processed/model_safe/` |
| Mutable | NO | YES (regenerable) | YES (regenerable) | YES (regenerable) |
| Contains IPs | N/A (PCAP) | YES | YES | **NO** |
| Contains ports | N/A (PCAP) | YES | YES | **NO** |
| Contains SNI text | N/A (PCAP) | YES | YES | **NO** (boolean only) |
| Contains abs timestamps | N/A (PCAP) | YES | YES | **NO** (duration only) |
| Contains MACs | N/A (PCAP) | NO (stripped at parse time) | NO | NO |
| Format | `.pcap` | Parquet | Parquet | Parquet |
| Git-tracked | NO | NO | NO | NO |

---

## 9. PCAP Validation

Before any packet is parsed, each PCAP file undergoes validation:

1. **Magic-byte check:** Verify the file starts with `0xd4c3b2a1` (little-endian pcap) or `0xa1b2c3d4` (big-endian pcap). Reject pcapng for now (dpkt limitation).
2. **Readability:** Attempt to instantiate a `dpkt.pcap.Reader`. If it throws, reject the file.
3. **Non-empty:** At least 1 packet must be readable.
4. **SHA-256 checksum:** Computed and stored in the processing manifest for reproducibility.
5. **Size bounds:** Log a warning if the PCAP exceeds 500 MB (to avoid memory issues with dpkt's streaming reader).

Failed validations are logged but do not halt the pipeline. The manifest records `validation_status = FAILED` for rejected files.

---

## 10. Flow Reconstruction

### 10.1 Flow Key

A bidirectional flow is identified by a **canonical 5-tuple**:

```
flow_key = sorted_tuple(src_ip, dst_ip, src_port, dst_port, protocol)
```

The tuple is sorted so that `(A, B, portA, portB, TCP)` and `(B, A, portB, portA, TCP)` map to the same flow. The **initiator** (forward direction) is defined as the endpoint that sent the first observed packet in the flow.

### 10.2 Timeout

Flows are separated by an **idle timeout**:

- **Default:** 120 seconds (configurable via `config.py`).
- **Rationale:** This is a common value in the literature (CICFlowMeter uses 120s). However, the optimal timeout for encrypted C2 traffic is unknown.
- **Status:** `PENDING_PILOT_VALIDATION` â€” the timeout will be validated during Step 3 (pilot run) by examining the distribution of inter-packet gaps.

### 10.3 Session Boundaries

In addition to idle timeout, a new flow is started if:
- A TCP SYN is observed after the flow has been idle.
- A TCP FIN/RST terminates the connection.

For UDP flows (if any TLS-over-UDP appears), only the idle timeout applies.

### 10.4 Edge Cases

| Case | Handling |
|------|----------|
| Retransmissions | Included in packet count and byte count. A `retransmission_count` field may be added in a future iteration. |
| Fragmented IP packets | Reassembled at the IP layer by dpkt where possible. Fragments that cannot be reassembled are skipped with a warning. |
| Malformed packets | Skipped. Error count logged per PCAP. |
| Duplicate packets | Included in the flow. Cross-flow deduplication occurs at the PROCESSED stage. |
| Zero-payload packets (ACKs) | Included in packet count but excluded from `packet_lengths` sequences (which track payload lengths only). |

---

## 11. TLS Detection

### 11.1 TLS Record Identification

TLS is detected by inspecting TCP payload bytes, NOT by port number.

```
if payload[0] == 22:  # ContentType.Handshake
    â†’ TLS handshake record detected
```

Additional content types (20=ChangeCipherSpec, 21=Alert, 23=ApplicationData) are noted but not deeply parsed.

### 11.2 ClientHello Detection

Within a Handshake record, `handshake_type == 1` indicates a ClientHello. The parser extracts:

| Field | Extraction Method |
|-------|-------------------|
| `legacy_version` | Bytes 9-10 of the handshake |
| `cipher_suites` | Parsed from the cipher suite list, GREASE values stripped |
| `extensions` | Parsed iteratively, GREASE values stripped |
| `sni_value` | From extension type 0 (server_name) |
| `alpn` | From extension type 16 |
| `supported_versions` | From extension type 43 (indicates TLS 1.3 capability) |
| `signature_algorithms` | From extension type 13 |

### 11.3 ServerHello Detection

`handshake_type == 2` indicates a ServerHello. The parser extracts:

| Field | Extraction Method |
|-------|-------------------|
| `negotiated_version` | From legacy field or `supported_versions` extension |
| `selected_cipher` | Single cipher suite value |
| `extensions` | Parsed iteratively |

### 11.4 TLS Version Determination

The **negotiated TLS version** for a flow is determined hierarchically:

1. If ServerHello contains `supported_versions` extension with value `0x0304` â†’ `"1.3"`
2. Else if ServerHello `legacy_version` is `0x0303` â†’ `"1.2"`
3. Else if only ClientHello is available â†’ version from `supported_versions` if present, else `legacy_version`
4. Else â†’ `"unknown"`

### 11.5 Non-TLS Handling

Flows where no TLS record is detected are tagged:
- `tls_detected = False`
- `tls_version = "none"`
- `clienthello_present = False`
- `serverhello_present = False`

These flows are preserved in the INTERIM/PROCESSED output (for completeness) but excluded from the primary MODEL-SAFE research dataset, which requires TLS presence.

---

## 12. Label Handling

### 12.1 Original Labels

Each dataset adapter provides the original label exactly as it appears in the source data. No transformation is applied to `label_original`.

### 12.2 Normalized Labels

The pipeline maps original labels to a controlled vocabulary:

| Normalized Label | Meaning | Used When |
|------------------|---------|-----------|
| `MALICIOUS` | Flow originates from a known malicious capture | DS-008 (all flows) |
| `BENIGN_VALIDATION` | Flow from a dataset with no malware, used for validation | DS-004 (all flows) |
| `BENIGN` | Flow explicitly labeled benign in a unified dataset | DS-006/DS-007 (future) |
| `UNKNOWN` | Label cannot be determined | Fallback |

> **Critical:** `BENIGN_VALIDATION` is deliberately distinct from `BENIGN`. When DS-008 and DS-004 are combined, the model is trained on `MALICIOUS` vs `BENIGN_VALIDATION`. This naming makes it impossible to accidentally conflate "validated benign from a unified dataset" with "assumed benign from a different capture environment."

### 12.3 Label Provenance

Every label carries:
- `label_source`: How the label was assigned (e.g., `mta_filename_convention`, `cipherspectrum_metadata`)
- `label_confidence`: `HIGH` (expert-curated), `MEDIUM` (automated), `LOW` (inferred)

---

## 13. Leakage Control

### 13.1 Three-Tier Strategy

Leakage control is implemented as a **view transformation**, not data destruction. Raw identifiers are always preserved in earlier tiers for audit.

### 13.2 Field Disposition

| Field | INTERIM | PROCESSED | MODEL-SAFE | Rationale |
|-------|---------|-----------|------------|-----------|
| `src_ip` | âœ… | âœ… | âŒ DROPPED | Trivially separates capture environments |
| `dst_ip` | âœ… | âœ… | âŒ DROPPED | Same as above |
| `src_port` | âœ… | âœ… | âŒ DROPPED | Ephemeral ports carry no behavioral signal; well-known ports leak service identity |
| `dst_port` | âœ… | âœ… | âŒ DROPPED | Port 443 is near-universal for TLS; other ports leak application identity |
| `protocol` | âœ… | âœ… | âŒ DROPPED | Nearly all TLS is TCP; this field would be constant |
| `timestamp_start` | âœ… | âœ… | âŒ DROPPED | Absolute time leaks capture date/environment |
| `timestamp_end` | âœ… | âœ… | âŒ DROPPED | Same as above |
| `sni_value` | âœ… | âœ… | âŒ DROPPED | Domain names trivially separate malware from benign |
| `sni_present` | âœ… | âœ… | âœ… RETAINED | Boolean presence is a legitimate TLS behavioral signal |
| `duration` | âœ… | âœ… | âœ… RETAINED | Relative duration is behavioral |
| `dataset_id` | âœ… | âœ… | âŒ DROPPED | Would allow the model to learn dataset identity |
| `capture_source` | âœ… | âœ… | âŒ DROPPED | Same as above |
| `source_file` | âœ… | âœ… | âŒ DROPPED | Same as above |
| MAC addresses | âŒ NOT EXTRACTED | â€” | â€” | Never parsed from the Ethernet layer |

### 13.3 Remaining Leakage Risks (Documented, Not Fully Mitigable)

| Risk | Severity | Mitigation | Status |
|------|----------|------------|--------|
| **RTT/network-latency artifacts in IAT** | HIGH | Statistical normalization in Phase 7 | PENDING_PHASE_7 |
| **MTU differences between capture environments** | MEDIUM | Packet-length distribution normalization | PENDING_PHASE_7 |
| **OS/browser fingerprint encoded in JA3/JA4** | HIGH | Cannot be mitigated without destroying signal; must be documented as limitation | DOCUMENTED |
| **ALPN correlation with dataset** | MEDIUM | Monitor ALPN distribution; may need to exclude from certain experiments | PENDING_PILOT |

---

## 14. Provenance

### 14.1 Per-Record Provenance

Every flow record carries `dataset_id`, `source_file`, `source_file_sha256`, `flow_id`, `pipeline_version`, and `extraction_timestamp`.

### 14.2 Processing Manifest

A JSON manifest is written to `data/processed/manifests/processing_manifest.json` after each pipeline run:

```json
{
    "pipeline_version": "0.1.0",
    "run_timestamp": "2026-08-16T10:00:00Z",
    "config_hash": "sha256_of_config_file",
    "datasets_processed": [
        {
            "dataset_id": "DS-008",
            "pcap_count": 2,
            "pcap_checksums": { "file.pcap": "sha256..." },
            "flow_count": 150,
            "tls_flow_count": 62,
            "error_count": 0
        }
    ],
    "total_flows": 300,
    "total_tls_flows": 180,
    "schema_version": "1.0.0"
}
```

---

## 15. Reproducibility

| Mechanism | Implementation |
|-----------|---------------|
| **Configuration file** | `pipeline/config.py` defines all tunable parameters (timeout, TLS detection thresholds, schema version). No magic numbers in processing code. |
| **Deterministic flow IDs** | `flow_id = sha256(canonical_5tuple + first_packet_timestamp)` â€” same input always produces same ID. |
| **PCAP checksums** | SHA-256 of every input PCAP recorded in manifest. |
| **Schema versioning** | Schema changes increment the version in `pipeline/schema.py`. Old processed data is invalidated. |
| **Pipeline versioning** | Semantic versioning in `pipeline/__init__.py`. |
| **No random operations** | Flow reconstruction and feature extraction are fully deterministic. |
| **Logging** | Python `logging` module writes structured logs to `data/processed/logs/`. |

---

## 16. Tooling

### 16.1 Selected Tools

| Tool | Role | Justification |
|------|------|---------------|
| **dpkt** (v1.9.8, installed) | Primary PCAP parser | Pure Python, lightweight, streaming reader, no external binary dependencies. Already validated on DS-008 PCAPs. |
| **Scapy** (installed) | Fallback parser / complex dissection | Used by existing `verify_ds003.py` and `verify_ds004.py`. Heavier than dpkt but provides robust packet reassembly. |
| **pandas** | DataFrame operations for interim processing | Standard, widely available. |
| **pyarrow** | Parquet I/O | Required for efficient columnar storage of flow records with nested lists (packet lengths, IATs). |
| **hashlib** (stdlib) | SHA-256 checksums and deterministic IDs | No additional dependency. |

### 16.2 Rejected Tools

| Tool | Reason |
|------|--------|
| **tshark/Wireshark** | Not installed on this system. Would add a heavyweight binary dependency. |
| **pyshark** | Wrapper around tshark; fails without tshark binary. |
| **NFStream** | Powerful but adds significant C dependency (nDPI). Overkill for this project's scale. |
| **CICFlowMeter** | Java-based, hard to integrate into a Python pipeline. Feature extraction logic would be opaque. |
| **PySpark** | Mentioned in Phase 5 closure report, but the dataset scale (~100k flows) does not justify distributed processing. Single-machine pandas/pyarrow is sufficient and simpler. |

### 16.3 Dependencies to Install

```
pip install pandas pyarrow
```

dpkt, scapy, hashlib (stdlib) are already available.

---

## 17. Configuration

All pipeline parameters are centralized in `pipeline/config.py`:

```python
# Pipeline version
PIPELINE_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0.0"

# Directories
RAW_DATA_DIR = "data/raw"
INTERIM_DIR = "data/interim"
PROCESSED_DIR = "data/processed"
MODEL_SAFE_DIR = "data/processed/model_safe"

# Flow reconstruction
FLOW_IDLE_TIMEOUT_SECONDS = 120      # PENDING_PILOT_VALIDATION
FLOW_MAX_DURATION_SECONDS = 3600     # Cap at 1 hour
FLOW_MIN_PACKETS = 1                 # Minimum packets to constitute a flow

# TLS detection
TLS_HANDSHAKE_CONTENT_TYPE = 22
TLS_CLIENTHELLO_TYPE = 1
TLS_SERVERHELLO_TYPE = 2

# Packet length sequences
MAX_PACKET_SEQUENCE_LENGTH = 1000    # Truncate sequences longer than this

# Quality control
MIN_FLOW_DURATION_SECONDS = 0.0      # Allow zero-duration flows (single-packet)
MAX_FLOW_DURATION_SECONDS = 7200     # Flag flows longer than 2 hours
```

---

## 18. Error Handling

| Error Type | Handling | Logged |
|------------|----------|--------|
| Unreadable PCAP | Skip file, log error, record in manifest | YES |
| Malformed packet | Skip packet, increment error counter | YES |
| TLS parsing failure | Record `tls_detected=True` but leave handshake fields as defaults | YES |
| Missing label metadata | Set `label_original="UNKNOWN"`, `label_confidence="LOW"` | YES |
| Oversized PCAP (>500MB) | Process with warning; streaming reader handles memory | YES (WARNING) |
| Schema validation failure | Record flagged in QC report, not silently dropped | YES |

The pipeline follows a **skip-and-log** strategy: individual packet or flow errors never halt the entire run. The QC report at the end summarizes all errors for manual review.

---

## 19. Quality-Control Checks

After extraction, the following automated checks run on the PROCESSED output:

| Check | Description | Action on Failure |
|-------|-------------|-------------------|
| **Schema conformance** | Every field present, correct type | Flag record |
| **Null audit** | Count nulls per column; alert if >5% | Log warning |
| **TLS consistency** | If `clienthello_present=True` then `tls_detected` must be `True` | Flag record |
| **Duration bounds** | Flag flows with `duration > MAX_FLOW_DURATION_SECONDS` or negative duration | Flag record |
| **Packet count consistency** | `forward_packet_count + reverse_packet_count == packet_count` | Flag record |
| **Byte count consistency** | `forward_byte_count + reverse_byte_count == byte_count` | Flag record |
| **Sequence length** | `len(packet_lengths) == packet_count` (for payload-bearing packets) | Flag record |
| **Label coverage** | Every record has a non-null `label_normalized` | Flag record |
| **Duplicate detection** | Flows with identical `flow_id` across PCAPs | Flag duplicates |
| **Dataset balance** | Log class distribution (MALICIOUS vs BENIGN_VALIDATION counts) | Informational |

QC results are written to `data/processed/manifests/qc_report.json`.

---

## 20. Phase 6 Step Dependencies

| Step | Title | Depends On | Produces |
|------|-------|------------|----------|
| **Step 1** | Architecture Design (this document) | Phase 5 closure | Architecture document |
| **Step 2** | Core Pipeline Implementation | Step 1 | `pipeline/` package: parser, flow reconstruction, TLS extraction |
| **Step 3** | Pilot Run on Existing Samples | Step 2 | Interim Parquet files; validation of timeout, schema, TLS parsing |
| **Step 4** | Dataset Adapter Implementation | Step 2 | `adapters/ds008_adapter.py`, `adapters/ds004_adapter.py` |
| **Step 5** | Label Ingestion & Normalization | Step 4 | Labeled flow records |
| **Step 6** | Leakage Control Implementation | Step 5 | MODEL-SAFE Parquet output |
| **Step 7** | Quality Control & Validation | Step 6 | QC reports, error logs |
| **Step 8** | Full Pipeline Integration Test | Steps 2â€“7 | End-to-end validated output |
| **Step 9** | Documentation & Phase 6 Closure | Step 8 | Updated research docs, Phase 7 handoff spec |

---

## 21. Open Technical Decisions

| Decision | Options | Current Default | Status |
|----------|---------|-----------------|--------|
| Flow idle timeout | 30s, 60s, 120s, 300s | 120s | PENDING_PILOT_VALIDATION |
| Parquet compression | snappy, gzip, zstd | snappy | Low priority; snappy is standard |
| Packet-length definition | IP total length vs TCP payload length | TCP payload length (excluding headers) | Tentative; TCP payload is more relevant for encrypted content analysis |
| Handling of non-TLS flows | Include in PROCESSED, exclude from MODEL-SAFE | Exclude from MODEL-SAFE | Confirmed by research scope |
| IAT normalization | Raw seconds vs Z-score vs min-max | Raw seconds (normalization deferred to Phase 7) | Phase 7 responsibility |
| pcapng support | dpkt does not natively support pcapng | Reject pcapng; convert externally if needed | Acceptable for current datasets |
| Maximum flows per PCAP | No limit vs configurable cap | No limit | Review if memory becomes an issue |

---

## 22. Scientific Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Dataset-source leakage** | CRITICAL | Three-tier data architecture ensures leakage-prone fields are never in the model feature set. Documented as a known limitation. |
| **Capture-environment confounding in IAT/RTT** | HIGH | Statistical normalization deferred to Phase 7. Cannot be fully eliminated without a unified dataset. |
| **JA3/JA4 encoding OS/browser identity** | HIGH | JA3/JA4 inherently encode the TLS implementation. If DS-004 and DS-008 use different OS/browsers, fingerprints will trivially separate them. Must be analyzed and documented. |
| **Incomplete TLS parsing** | MEDIUM | The custom TLS parser (from `verify_ds004.py`) has been empirically validated on DS-004 and DS-008 samples. Edge cases (fragmented ClientHello, TLS-in-TLS) may be missed. |
| **Flow reconstruction artifacts** | MEDIUM | Timeout-based flow reconstruction may split long-lived C2 sessions or merge unrelated short flows. Pilot validation (Step 3) will assess this. |
| **Label quality for DS-008** | MEDIUM | MTA labels are expert-curated per-PCAP but not per-flow. A PCAP labeled "XLoader" may contain background DNS/NTP traffic that is not malicious. |

---

## 23. Phase 7 Interface

Phase 7 (Feature Engineering) receives the **MODEL-SAFE** Parquet file from `data/processed/model_safe/flows_model_safe.parquet`.

### 23.1 What Phase 7 Receives

A validated flow-level dataset containing:

- **Flow behavioral features:** `duration`, `packet_count`, `forward_packet_count`, `reverse_packet_count`, `byte_count`, `forward_byte_count`, `reverse_byte_count`, `packet_lengths`, `forward_packet_lengths`, `reverse_packet_lengths`, `iat_sequence`, `forward_iat_sequence`, `reverse_iat_sequence`
- **TLS structural metadata:** `tls_detected`, `tls_version`, `clienthello_present`, `serverhello_present`, `sni_present`, `alpn_first`, `cipher_suite_count`, `extension_count`, `supported_versions_present`
- **Labels:** `label_original`, `label_normalized`, `label_source`, `label_confidence`, `malware_family`

### 23.2 What Phase 7 Will Compute

Phase 7 is responsible for:

1. **JA3 hash computation** from raw ClientHello fields (cipher suites, extensions, curves, point formats).
2. **JA3S hash computation** from raw ServerHello fields.
3. **JA4 fingerprint computation** using the FoxIO specification.
4. **Statistical flow features** (mean, std, min, max, quantiles of packet lengths and IATs).
5. **Feature encoding** (one-hot encoding of JA3/JA4 categories, numerical scaling).
6. **Feature selection** for the five experimental configurations (A through E).

### 23.3 What Phase 7 Does NOT Receive

- IP addresses
- Port numbers
- MAC addresses
- Absolute timestamps
- SNI domain strings
- Dataset identifiers
- Source filenames
- Any field from the PROVENANCE or RAW tiers

### 23.4 Contract

Phase 6 guarantees that every record in the MODEL-SAFE output:
- Has a valid `label_normalized` âˆˆ {`MALICIOUS`, `BENIGN_VALIDATION`, `BENIGN`, `UNKNOWN`}
- Has `tls_detected = True`
- Has passed all QC checks (or is explicitly flagged)
- Contains non-null packet-length and IAT sequences
- Is traceable back to its source via the PROCESSED tier (for debugging)
