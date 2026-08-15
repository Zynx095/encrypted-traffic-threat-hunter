# Phase 6 Step 3 â€” PCAP Integrity and Protocol Validation

## 1. Objective
Empirically characterize the ingested PCAPs before full flow reconstruction. Establish structural validity, packet/byte composition, transport protocols, and passive TLS properties without relying on port-based heuristics, while preserving environmental safety.

## 2. Input Captures
Processed using `data/manifests/` output from Phase 6 Step 2:
- **DS-008 (Malware-Traffic-Analysis)**: 2 representative PCAPs
- **DS-004 (CipherSpectrum)**: 6 representative PCAPs

## 3. Integrity Results
- SHA-256 validation confirmed that PCAP integrity was strictly maintained during ingestion.
- All 8 PCAPs completed streaming parsing sequentially via `dpkt`.
- No empty captures were recorded.
- No `pcapng` format exceptions occurred, as they were excluded during Step 2.

## 4. Packet-Level Results
- **DS-008**: Processed 64,546 total packets across 2 files.
- **DS-004**: Processed 396 total packets across 6 files.
- IPv4 comprises virtually 100% of all IP traffic. IPv6 was 0.0% across all evaluated sample PCAPs.
- ARP and minor unknown layer-2 traffic comprised <1% of the total packets.

## 5. TCP Results
- **DS-008**: 99.89% and 97.98% TCP composition in the two PCAPs.
- **DS-004**: 100.0% TCP composition across all six PCAPs.
- Zero-payload TCP packets represent approximately 40-50% of the TCP volume, corresponding to standard handshake (SYN/ACK) and teardown (FIN/RST) sequences, plus ACKs for data segments.
- Retransmissions were logged as `NOT_IMPLEMENTED` as reliable estimation is deferred to the flow reconstruction stage.

## 6. UDP Results
- **DS-008**: Contains trace amounts of UDP (0.07% and 1.34% of packets).
- **DS-004**: 0.0% UDP traffic in the tested samples.
- The UDP payload observed in DS-008 amounts to DNS and auxiliary protocols. No definitive QUIC presence was extracted as part of this step's scope.

## 7. TLS Detection
- Passive structural TLS detection (inspecting packet payload for Content Type 22 and Handshake Type 1/2) successfully identified TLS in **both** datasets without relying on port 443.
- All PCAPs demonstrated TLS presence.

## 8. ClientHello Findings
- ClientHello packets were consistently detected across the datasets.
- TLS 1.3 was identified structurally by inspecting the `supported_versions` extension rather than the legacy `0x0303` record layer version.
- SNI and ALPN extensions were successfully parsed and counted:
  - **DS-008**: 45 ClientHellos detected in the XLoader sample. 45 SNI extensions (100% presence) and 34 ALPN extensions (75% presence).
  - **DS-004**: 1 ClientHello per sample (100%). SNI was present in 5 out of 6 samples. ALPN was present in 5 out of 6 samples.
- GREASE values (0x0A0A etc.) were appropriately skipped during extension iteration.

## 9. ServerHello Findings
- ServerHello packets were observed in parity with ClientHello packets, verifying bidirectional handshake visibility for JA3S extraction downstream.
- Actual cipher suite selection metrics are deferred to Phase 6 Step 4 (Flow Reconstruction & JA3 extraction).

## 10. Flow Candidate Findings
- **DS-008**: Generated 541 distinct 5-tuple flow candidates in one capture and over 2,000 in another.
- **DS-004**: Generated exactly 1 5-tuple flow candidate per PCAP.
- The flow timeout threshold remains `PENDING_PILOT_VALIDATION` as flow duration calculations are not fully solidified until Step 4.

## 11. Malformed / Edge Cases
- `dpkt.NeedData` (truncated packets) occurrences: 0.
- `dpkt` parsing exceptions resulting in malformed packets: 0.
- Safe Linux Cooked Capture (SLL) and Ethernet Layer 2 abstractions correctly mitigated errors.
- No dataset crashes occurred.

## 12. DS-008 vs DS-004 Comparison
- **Scale**: DS-008 captures are full sandbox environments capturing hours/minutes of background noise, whereas DS-004 samples are heavily filtered single-flow extractions.
- **TLS Version**: DS-008 exhibits a mix of TLS 1.2 and TLS 1.3. DS-004 exhibits TLS 1.3 and TLS 1.0 depending on the specific sample flow.
- **UDP**: DS-008 contains baseline UDP noise (DNS/NTP). DS-004 is artificially stripped of all UDP traffic in these samples.

## 13. Scientific Interpretation
The PCAPs structurally support the required feature space (bidirectional flow statistics and JA3/JA3S/JA4 feasibility). TLS versions are observable. However, the extreme single-flow nature of the DS-004 samples indicates they are synthetic/extracted. Normalization algorithms must be robust against zero-background-noise flow dynamics.

## 14. Capture-Environment Differences
- DS-008 (Sandbox): Realistic, noisy, multi-flow environment.
- DS-004 (Enterprise filter): Highly sanitized, single-flow environment.
- These differences highlight the need for careful feature selection to prevent the model from simply learning "sandbox vs filtered" instead of "malicious vs benign".

## 15. Failures
- An initial implementation assumed all `dpkt` `datalink` types were standard Ethernet. This was resolved by properly differentiating `DLT_LINUX_SLL`, `DLT_EN10MB`, and `DLT_RAW`.

## 16. Limitations
- TLS extraction only parsed plain-text handshake records. Encrypted handshakes (e.g., ECH) were not explicitly characterized.
- Retransmission detection was deferred.

## 17. Phase 6 Step 4 Input Contract
Step 3 empirically verified that `dpkt` successfully extracts packet-level TCP, UDP, and TLS primitives from all relevant Phase 6 inputs without memory exhaustion or exception-induced crashes. Flow reconstruction (Step 4) may confidently iterate these packets and aggregate 5-tuples utilizing a robust bidirectional timeout strategy.
