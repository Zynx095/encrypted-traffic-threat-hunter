# Phase 6.5 Step 2 — MTA Empirical Verification

## 1. Objective
Perform targeted acquisition and empirical verification of the highest-value MTA candidates identified in Step 1. The goal is to determine which newly discovered MTA captures actually contain valid, modern TLS-encrypted malware traffic with extractable JA3 and JA4 fingerprints, suitable for expanding the DS-008 malicious corpus.

## 2. Candidate Selection
The top 10 candidates selected for empirical verification were:
1. **MTA-C018** (2025-09-24) — Lumma Stealer + Ghostsocks
2. **MTA-C006** (2026-04-16) — Lumma + SectopRAT + ArechClient2
3. **MTA-C021** (2025-08-20) — NetSupport RAT + StealC v2
4. **MTA-C040** (2024-08-26) — GuLoader + Remcos RAT
5. **MTA-C045** (2024-03-06) — Pikabot + Meduza Stealer
6. **MTA-C049** (2024-01-30) — DarkGate
7. **MTA-C003** (2026-08-06) — Remcos RAT 7.2.5 Pro
8. **MTA-C039** (2024-09-11) — Remcos RAT + XLoader
9. **MTA-C022** (2025-08-15) — Lumma Stealer + SectopRAT
10. **MTA-C015** (2025-11-19) — XWorm

## 3. Access Procedure
The MTA About page (`https://www.malware-traffic-analysis.net/about.html`) was queried prior to download. The page structure was parsed to retrieve the currently documented password scheme:
- **DOCUMENTED**: The password scheme for archives is `infected_YYYYMMDD` (based on the date of the post).
- Passwords were not hard-coded into the repository but derived dynamically during the extraction pipeline.

## 4. Download Methodology
- A custom pipeline script (`step65_step2_run.py`) scraped the exact ZIP file URLs from each candidate's index page.
- Archives were downloaded to the ignored directory `data/verification/mta_stage65/`.
- Download success rate: 10/10 candidates.

## 5. Safety Controls
- All downloaded files were kept in `.gitignore` paths.
- Extraction was limited to files ending in `.pcap` or `.pcapng`.
- No executables, malware payloads, or scripts were extracted or executed.
- All PCAPs were parsed passively using Python `dpkt`.

## 6. PCAP Integrity
- **EMPIRICALLY VERIFIED**: All 10 downloaded ZIP archives contained valid, parsable PCAP or PCAPNG files.
- `pipeline/pcap_validator.py` successfully validated the captures.

## 7. TLS Results
- **EMPIRICALLY VERIFIED**: 10/10 PCAPs contained traffic over port 443.
- **EMPIRICALLY VERIFIED**: 10/10 PCAPs contained valid TLS records.
- TLS 1.2 presence: 5/10 PCAPs.
- TLS 1.3 presence: 7/10 PCAPs. (Some captures contained both).

## 8. ClientHello Results
- **EMPIRICALLY VERIFIED**: 9/10 PCAPs contained at least one valid, unencrypted ClientHello message.
- (MTA-C003 contained TLS traffic but no initial ClientHello handshake, suggesting a mid-session capture or non-standard protocol masquerading as TLS).

## 9. ServerHello Results
- **EMPIRICALLY VERIFIED**: 9/10 PCAPs contained valid ServerHello responses.

## 10. JA3 Results
- **EMPIRICALLY VERIFIED**: JA3 strings and hashes were successfully computed for 9/10 PCAPs using `pipeline.tls_fingerprinting`.

## 11. JA3S Results
- **EMPIRICALLY VERIFIED**: JA3S strings and hashes were successfully computed for 9/10 PCAPs.

## 12. JA4 Results
- **EMPIRICALLY VERIFIED**: JA4 fingerprints were successfully computed for 9/10 PCAPs.

## 13. Flow Reconstruction Results
- **EMPIRICALLY VERIFIED**: 10/10 PCAPs produced valid bidirectional flows.
- Flow volumes varied significantly:
  - High volume: MTA-C006 (54 TLS flows), MTA-C045 (51 TLS flows).
  - Low volume: MTA-C039 (1 TLS flow).

## 14. Malware-Family Validation
- **DOCUMENTED**: Malware families were assumed correct based on MTA documentation.
- **INFERRED**: Due to safety controls, dynamic detonation was not performed. Malware identity was not independently verified beyond the provided network IOCs matching the documented families. Label confidence remains `DOCUMENTED_SOURCE`.

## 15. Candidate Quality Ranking
Based on empirical TLS volume, JA4 applicability, and multi-family diversity:

**HIGH (5 candidates):**
- MTA-C006 (Lumma + SectopRAT + ArechClient2): 54 TLS flows, JA4 YES.
- MTA-C045 (Pikabot + Meduza Stealer): 51 TLS flows, JA4 YES.
- MTA-C022 (Lumma + SectopRAT): 11 TLS flows, JA4 YES.
- MTA-C018 (Lumma + Ghostsocks): 9 TLS flows, JA4 YES.
- MTA-C021 (NetSupport + StealC v2): 7 TLS flows, JA4 YES.

**MEDIUM (4 candidates):**
- MTA-C049 (DarkGate): 4 TLS flows, JA4 YES.
- MTA-C040 (GuLoader + Remcos RAT): 3 TLS flows, JA4 YES.
- MTA-C015 (XWorm): 3 TLS flows, JA4 YES.
- MTA-C039 (Remcos RAT + XLoader): 1 TLS flow, JA4 YES.

## 16. Rejected Candidates
- **MTA-C003** (Remcos RAT 7.2.5 Pro): REJECTED. Although 1 TLS flow was present, no ClientHello could be extracted, meaning no JA3 or JA4 fingerprint could be generated.

## 17. Failure Analysis
- Initial scraping assumed `href="*.zip"` was always the PCAP archive. This failed because some entries included multiple zips (e.g., `notes.txt.zip`). The scraping logic was updated to prioritize `*pcap.zip`.
- `pcap_validator.py` required a `pathlib.Path` input, which was corrected in the automation script.
- `pcapng` format support was properly routed to `dpkt.pcapng` parser during flow reconstruction.

## 18. Recommended Expanded DS-008 Corpus
Based on the high empirical success rate (9/10 JA4-capable captures), a **DS-008 EXPANSION IS STRONGLY RECOMMENDED**.

The expanded corpus should integrate the 5 HIGH-quality candidates and optionally the 4 MEDIUM-quality candidates to create a highly robust, multi-family modern TLS dataset.

**Best Newly Verified Candidates:**
1. MTA-C006
2. MTA-C045
3. MTA-C022
4. MTA-C018
5. MTA-C021

## 19. Scientific Limitations
- We cannot guarantee the absolute absence of benign background traffic within these PCAPs, though MTA typically filters for malware activity.
- The `DOCUMENTED_SOURCE` confidence for malware families relies entirely on the accuracy of the original researcher.
- Low-flow captures (e.g., MTA-C039 with 1 flow) provide very sparse behavioral features, relying heavily on the JA4 fingerprint for classification.

## 20. Step 2 Conclusion
The empirical verification phase was a definitive success. 90% of the targeted top 10 candidates yielded high-quality JA4 fingerprints and bidirectional TLS flows. The repository has the empirical data necessary to proceed with a significant and scientifically sound expansion of DS-008.
