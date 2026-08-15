# Phase 6 Step 4 â€” Bidirectional Flow Reconstruction

## 1. Objective
Implement deterministic bidirectional flow reconstruction mapping independent network packets into candidate semantic flow representations. This module bridges raw PCAP frames into sequence objects ready for future feature extraction, preserving crucial properties like order, relative timestamps, byte distributions, and TLS correlation.

## 2. Flow Definition
A bidirectional flow is established dynamically by grouping packets according to a canonical 5-tuple:
`(min(ep_src, ep_dst), max(ep_src, ep_dst), protocol)`
This correctly unifies A â†’ B and B â†’ A interactions.

## 3. Canonical Flow Key
The canonical flow key establishes identity independent of direction:
- `endpoint_min`: Lexicographically lower combination of IP:Port.
- `endpoint_max`: Lexicographically higher combination of IP:Port.
- `protocol`: Transport protocol ("TCP" or "UDP").
The choice of canonical sort is deterministic, explicitly defined in code, and avoids assumption of client/server role based purely on endpoints.

## 4. Direction Assignment
Directionality within the flow is resolved observationally:
- The source endpoint of the **first observed packet** in the flow is deemed the `FORWARD` direction.
- The alternate endpoint is deemed the `REVERSE` direction.
This holds irrespective of IP space or designated server ports (e.g. 443). If TLS semantics override this later (e.g. ServerHello observed originating from the Forward endpoint), that semantic inversion will be executed downstream.

## 5. Flow IDs
To preserve stateless determinism, the Flow ID is a SHA-256 hash containing:
`{PCAP_SHA256}_{Canonical_Key}_{Flow_Instance}`
This provides mathematical assurance that reprocessing the exact same PCAP with the exact same architecture unconditionally produces the exact same Flow IDs, free of UUID randomness or timestamp variance.

## 6. Flow Instances
A singular 5-tuple may be reused for multiple successive flows in a capture timeline. Flow uniqueness is defined by the identity plus its *instance* index. A new instance triggers upon:
- Configurable Idle Timeout expiration.
- Post-termination sequence detection (a new SYN appearing after a FIN/RST has previously finalized the sequence).

## 7. Idle Timeout
> [!NOTE]
> The Idle Timeout triggers flow segmentation if `CurrentPacket.timestamp - CurrentFlow.end_time > TIMEOUT`.

`FLOW_IDLE_TIMEOUT` is currently configured to the `DEFAULT_CONFIGURATION` of 120.0 seconds.
The absolute, definitive scientific threshold remains **`PENDING_PILOT_VALIDATION`** and is subject to tuning during experimental pilot stages.

## 8. TCP Termination
TCP flows are softly closed upon observing a packet bearing the `FIN` or `RST` flag. Subsequence packets mapping to the same canonical key immediately trigger a new Flow Instance to represent connection reuse or independent retries.

## 9. UDP Flow Boundaries
Lacking explicit termination flags, UDP boundaries are delineated exclusively via:
1. 5-tuple key.
2. The `FLOW_IDLE_TIMEOUT` threshold.

## 10. Packet Ordering
Original PCAP index order is inherently preserved. In scenarios containing equal microsecond timestamps across sequential frames, the inherent sequential iteration array acts as a deterministic tiebreaker. Order mapping relies strictly upon index array insertion order.

## 11. Packet Length Representation
Currently capturing the total **IP-level byte length**, represented as:
- `byte_count`
- `forward_byte_count` / `reverse_byte_count`
- Sequence array: `packet_lengths`

> [!NOTE]
> **`PENDING_PILOT_VALIDATION`**: The scientific decision to utilize IP Total Length vs. Transport Payload Length is deferred. Both can be supported or derived, but IP Total Length serves as the current foundational representation because it factors in network-layer noise, which is crucial for Encrypted Traffic Threat Hunting behavioral profiling.

## 12. Timestamp Representation
Absolute epoch timestamps are retained merely for the `start_time` and `end_time` bounds to maintain interim data integrity.
For behavioral ML representations, times are flattened into a `relative_times` array (zero-anchored based upon `flow_start_time`).
> [!IMPORTANT]
> Absolute timestamps will be strictly purged before exporting the final MODEL-SAFE schema to prevent temporal ML leakage.

## 13. Flow Statistics
The reconstructor aggregates and exports:
- `flow_id`, `flow_instance`, `dataset_id`, `source_file`, `protocol`
- `start_time`, `end_time`, `duration`
- `packet_count`, `forward_packet_count`, `reverse_packet_count`
- `byte_count`, `forward_byte_count`, `reverse_byte_count`
- `forward_endpoint`, `reverse_endpoint`
- Sequence Arrays: `packet_lengths`, `direction_sequence`, `relative_times`, `tcp_flags`, `tls_candidate_sequence`

## 14. TLS Association
TLS payload interaction is represented via a binary boolean array mapping 1:1 with the packet sequence (`tls_candidate_sequence`), marking precisely which packets contained `Content Type: 22` and standard handshake signatures, bypassing arbitrary port assumptions.

## 15. Memory Strategy
The `FlowReconstructor` relies on single-pass PCAP streaming. Active flows are dynamically pruned and flushed into completed memory buffers (or disk serialization paths) whenever closed by FIN/RST or idle timeout. This prevents continuous memory accretion during extensive sandbox captures.

## 16. Dataset Differences
Empirical Reconstruction Validation conclusively proved environmental disparities:
- **DS-004 (CipherSpectrum)**: All samples reconstructed precisely **1 Flow Instance** each.
- **DS-008 (Malware-Traffic-Analysis)**: Reconstructed **74** and **1380** Flow Instances respectively.

## 17. Validation Rules
- All output flow lengths consistently mirror their packet counts.
- Forward bounds + Reverse bounds strictly equal Total bounds.
- Start times are unconditionally <= End times.
- Zero absolute timestamps leak into relative arrays.

## 18. Tests
- Created `tests/test_flow_reconstruction.py` comprising 8 deep-level functional invariant tests.
- Re-run invariance confirmed.
- All testing invariants passed successfully.

## 19. Known Limitations
- Retransmission filtering remains explicitly **`NOT_IMPLEMENTED`** and will be left to raw packet behavioral inference or later extraction modules if required.
- UDP traffic representing streaming continuous protocols could span theoretically indefinite lengths if packet gaps never exceed 120s.

## 20. Open Decisions
- Final flow idle timeout: `PENDING_PILOT_VALIDATION`
- Primary packet-length representation: `PENDING_PILOT_VALIDATION`
- Retransmission detection scope: `PENDING_PILOT_VALIDATION`
- Treatment of extremely long-lived TLS sessions (e.g. >24h C2 beacons): `PENDING_PILOT_VALIDATION`

## 21. Phase 5 Interface
The interim parquet outputs generated by this phase directly establish the fundamental bidirectional matrices ready to undergo precise JA3/JA3S/JA4 hashing feature injection in Phase 6 Step 5.
