# Phase 6 Step 5 — TLS Fingerprint Extraction

## 1. Objective
Implement dataset-agnostic, deterministic TLS fingerprint extraction (JA3, JA3S, JA4) directly from raw PCAP streams during flow reconstruction. This stage extracts critical TLS metadata into intermediate representations while maintaining robust handling of modern protocols (TLS 1.3, GREASE) and adhering strictly to empirical evidence present in the capture files.

## 2. TLS Handshake Parsing
Parsing avoids the fragile heuristic of `port == 443`. Instead, the system structurally identifies TLS records by inspecting the payload for `Content Type: 22 (Handshake)` and `Handshake Type: 1 (ClientHello) / 2 (ServerHello)`. Extraction acts upon raw bytes, ensuring preservation of packet order, extension lists, and cipher suites which standard flow parsers often omit or mutate.

## 3. JA3 Methodology
JA3 is constructed from the ClientHello in the canonical format:
`SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat`
- The `ja3_string` and `ja3_hash` (MD5) are explicitly preserved.
- GREASE values are actively filtered out from Ciphers, Extensions, and Supported Groups.

## 4. JA3S Methodology
JA3S is constructed from the ServerHello in the canonical format:
`SSLVersion,Cipher,SSLExtension`
- The `ja3s_string` and `ja3s_hash` (MD5) are explicitly preserved.
- GREASE values are actively filtered out.
- Extracted only when a valid ServerHello is positively observed.

## 5. JA4 Methodology
JA4 (ClientHello) extraction is rigorously aligned with the formal JA4 specification (`a_b_c` format):
- **Part A:** `t` (TCP) + `TLS Version` (`12`/`13`) + `SNI` (`d`/`i`/`n`) + `Cipher Count` + `Extension Count` + `ALPN`.
- **Part B:** 12-character SHA256 truncation of sorted hexadecimal cipher suites (excluding GREASE).
- **Part C:** 12-character SHA256 truncation of sorted hexadecimal extensions and signature algorithms (excluding SNI, ALPN, and GREASE).

## 6. GREASE Handling
Google's GREASE values (e.g., `0x0A0A`, `0x1A1A`) artificially mutate handshakes to prevent protocol ossification. The extraction systematically identifies GREASE using the rule `(val & 0x0F0F) == 0x0A0A` and securely excludes them from all cryptographic hashes and counts, ensuring consistent fingerprinting across Chrome/Edge sessions.

## 7. TLS 1.2 Handling
For TLS 1.2, the advertised TLS version safely falls back to the record version or client version field, rendering typical signatures seamlessly. 

## 8. TLS 1.3 Handling
TLS 1.3 mandates that the legacy record-layer version remains `0x0303` (TLS 1.2) for middlebox compatibility. Extraction correctly identifies TLS 1.3 exclusively via the presence of the `supported_versions` (Extension `43`). Consequently, JA4 correctly labels such sessions with the `13` version tag rather than miscategorizing them as `12`.

## 9. ClientHello / ServerHello Association
Handshakes are mapped deterministically to the bidirectional flow created in Step 4. Handshakes emitted from the flow's `FORWARD` or `REVERSE` endpoints independently trigger the parser, bridging client and server TLS characteristics under a single bidirectional flow vector.

## 10. Multiple Handshake Policy
A single network flow may theoretically contain multiple ClientHellos (e.g., renegotiation, session resumption). The implemented policy statically selects the **first observed valid ClientHello** and **first observed valid ServerHello** as the canonical handshakes representing the flow, preserving determinism and avoiding silent overwrites. 

## 11. SNI Handling
The `Server Name Indication` (SNI) is structurally detected to populate the JA4 `sni_indicator` (`d` vs `n`). For immediate structural validation, the raw domain is temporarily bypassed; the boolean flag `sni_present` is captured. *Raw domains must never reach MODEL-SAFE extraction directly due to dataset-source leakage.*

## 12. ALPN Handling
`Application-Layer Protocol Negotiation` (ALPN) strings are extracted and formatted explicitly for JA4 (i.e. first and last character of the first string, e.g. `h2`). The ALPN metadata remains in the intermediate tier. 

## 13. Determinism
Fingerprints are fundamentally stateless:
- Zero timestamps are injected into hashes.
- Arrays are consistently sorted (for JA4) or left in original wire-order (for JA3).
- Re-parsing the same capture file outputs mathematically identical JA3, JA3S, and JA4 strings.

## 14. Output Schema
The intermediate flow Parquet schema constructed in Step 4 was extended iteratively to include:
- `clienthello_present` (bool)
- `serverhello_present` (bool)
- `ja3_string` (str)
- `ja3_hash` (str)
- `ja3s_string` (str)
- `ja3s_hash` (str)
- `ja4` (str)
- `tls_version` (float)
- `tls_record_version` (float)
- `sni_present` (bool)
- `alpn` (str)

## 15. Validation Samples
Validation was conducted independently on the active pipeline via `step5_validation.py`. The script extracted Parquet geometries and compared outcomes with prior validation states documented in Phase 5.

## 16. DS-004 Results
DS-004 (CipherSpectrum) evaluation yielded a **100% extraction match**. All 6 samples natively derived 1 flow per capture, cleanly parsed TLS 1.3/1.0 ClientHellos, and generated corresponding JA4 fingerprints identical to historical Phase 5 verification findings.

## 17. DS-008 Results
DS-008 (Malware-Traffic-Analysis) evaluation yielded **62 discrete TLS flows** demonstrating structurally sound ClientHellos and ServerHellos. JA4 was successfully derived across 100% of applicable TLS candidate streams containing ClientHellos, isolating malware signals from the noisy baseline traffic. 

## 18. Test Results
Comprehensive unit tests (`tests/test_tls_fingerprinting.py`) were deployed and executed across:
- Known ClientHello / ServerHello payload structures.
- GREASE inclusion/exclusion boundaries.
- JA4 format string composition rules.
- Malformed header rejections.
**Result:** Passed successfully. 

## 19. Known Limitations
- The first-handshake selection policy might slightly skew behavioral aggregation if malware initiates complex intra-session TLS renegotiation patterns. 
- Fragmented TLS records across multiple TCP segments are currently not reassembled prior to fingerprinting; structural integrity relies on the ClientHello fitting into standard MTU boundaries.

## 20. Open Scientific Decisions
- Whether to utilize JA3, JA4, or a hybridized approach in ultimate feature selection (`PENDING_PILOT_VALIDATION`).
- Whether ALPN properties warrant distinct one-hot-encoded categorical columns outside of JA4 string representation (`PENDING_PILOT_VALIDATION`).
