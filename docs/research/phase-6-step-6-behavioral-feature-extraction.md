# Phase 6 Step 6 — Behavioral Feature Extraction

## 1. Purpose
The purpose of this step is to transform raw reconstructed network flows (INTERIM representation) into a deterministic behavioral feature representation suitable for machine learning (PROCESSED representation), without prematurely scaling or one-hot encoding the data. It derives statistical properties describing flow timing, directionality, and payload sizes while explicitly preserving TLS metadata.

## 2. Input Schema
The input consists of the Parquet schema produced by Phase 6 Steps 4 & 5 (e.g. `data/interim/flows/*.parquet`), which contains:
- Bidirectional flow counts (`packet_count`, `forward_packet_count`, `byte_count`, etc.)
- Arrays of sequences (`packet_lengths`, `relative_times`, `direction_sequence`)
- TLS metadata extracted from payloads (`ja3_hash`, `ja4`, `tls_version`, etc.)
- Provenance/labeling context (`dataset_id`, `source_file`)

## 3. Output Schema
The output schema transforms these inputs into approximately 85 derived numerical/categorical features representing families A through H. It preserves the underlying sequences safely as `sequence_packet_lengths`, `sequence_relative_times`, etc., ensuring subsequent phases can build sequence models if desired. No absolute IP addresses, ports, or raw domains are exposed.

## 4. Feature Families

### A. Flow-level statistics
- **Duration:** `flow_duration`
- **Volume:** `total_packets`, `total_bytes`, `forward_packets`, `reverse_packets`, `forward_bytes`, `reverse_bytes`
- **Rates:** `packets_per_second`, `bytes_per_second` (Safe divided to handle zero-duration flows, resulting in `NaN` where division is mathematically undefined)
- **Ratios:** `forward_packet_ratio`, `reverse_packet_ratio`, `forward_byte_ratio`, `reverse_byte_ratio`

### B. Directional statistics
- **Asymmetry:** `packet_count_asymmetry`, `byte_count_asymmetry` calculated as `(fwd - rev) / total`.
- **Directional length statistics:** `fwd_packet_length_*` and `rev_packet_length_*` (mean, median, std, min, max, percentiles).
- **Directional IAT statistics:** `fwd_iat_*` and `rev_iat_*`.

### C. Packet-length behavior
Calculated globally and directionally over the `sequence_packet_lengths` array:
- `packet_length_mean`, `packet_length_median`, `packet_length_std`
- `packet_length_min`, `packet_length_max`
- `packet_length_p25`, `packet_length_p75`, `packet_length_p90`, `packet_length_p95`

### D. Inter-arrival-time (IAT) behavior
Derived by taking the discrete difference (`np.diff`) of the `relative_times` array globally, and iteratively over forward-only and reverse-only timestamps. Computed to the standard statistical spread (mean, median, std, min, max, percentiles).

### E. Burst/temporal behavior
Bursts are arbitrarily defined as continuous sequences of packets unbroken by an idle gap exceeding `BURST_IDLE_THRESHOLD` (set to `1.0s`).
- `number_of_bursts`, `mean_burst_size`, `maximum_burst_size`
- `idle_gap_count`, `maximum_idle_gap`

### F. TLS structural behavior
Directly inherited safely from the interim tier:
- `tls_version`, `clienthello_present`, `serverhello_present`, `sni_present`, `alpn_value`

### G. TLS fingerprint features
Directly inherited without arbitrary vectorization, allowing experimental fusion pipelines access to raw hashes:
- `ja3_string`, `ja3_hash`, `ja3s_string`, `ja3s_hash`, `ja4`

### H. Label / Provenance
Derived via the `dataset_id` provenance indicator:
- `label`: `MALICIOUS` (DS-008) or `BENIGN_VALIDATION` (DS-004)

## 5. Mathematical Definitions
- **Packets per second:** `total_packets / flow_duration`
- **Packet Count Asymmetry:** `(forward_packets - reverse_packets) / total_packets`
- **IAT:** `relative_time[i] - relative_time[i-1]` for $i > 0$.

## 6. Missing-Value Handling
- Undefined divisions (e.g., rate of single-packet flow with 0.0 duration) yield `np.nan`.
- Statistical operations on empty sequences (e.g., standard deviation of standard deviation on a 1-packet flow, or `rev_iat_mean` on a forward-only flow) gracefully yield `np.nan`.
- TLS hashes explicitly yield `None` if the specific handshake required to generate them is absent from the flow geometry.

## 7. Sequence Preservation
To prevent information destruction, raw sequences are formally embedded inside the Parquet format using standard `list` structures:
- `sequence_packet_lengths`
- `sequence_relative_times`
- `sequence_directions`
- `sequence_tcp_flags`

## 8. Leakage Considerations
- Absolute timestamps are completely stripped; only relative arrival offsets (starting at 0.0s) remain.
- Source and destination IP addresses are stripped.
- Source and destination ports are stripped.
- MAC addresses are inherently stripped by the ingestion framework.
- `sni_present` boolean remains, but the actual raw SNI domain string is intentionally destroyed to prevent trivial environment fingerprinting.

## 9. Configurable Parameters
- `BURST_IDLE_THRESHOLD = 1.0` seconds: Determines the boundary condition splitting packet sequences into distinct bursts. This threshold must be evaluated empirically (`PENDING_PILOT_VALIDATION`).

## 10. Validation Results
- **Flows processed/generated:** 1460
- **Constraint Violations:** 0 (No infinite values, no negative timing/counts, bidirectional integrity maintained).
- **Leakage Violations:** 0 (No raw IPs, Ports, or domains detected in schemas).
- **Deterministic Check:** PASSED (Identical rows processed multiple times resulted in identical feature generation).

## 11. Known Limitations
- Background packet drops in the capture environment can artificially inflate IATs, splitting bursts inaccurately.
- `packets_per_second` and `bytes_per_second` skew infinitely high on artificially short synthetic traces without temporal spread.
- Directional IAT features exhibit large missingness across unidirectional scanner/flooder noise due to absolute absence of reverse traffic.

## 12. Open Scientific Decisions
- Should missing IAT features be statically imputed to 0.0, or should the ML architecture native handle missingness (`NaN`) during training? (`PENDING_PILOT_VALIDATION`)
- Should ALPN remain categorical string metadata or be transformed via One-Hot Encoding? (`PENDING_PILOT_VALIDATION`)
- Does `BURST_IDLE_THRESHOLD` of 1.0s accurately map to malware beaconing behavior, or does it require adjustment based on TCP keepalive architectures? (`PENDING_PILOT_VALIDATION`)
