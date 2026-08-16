# Phase 6.5 Step 3 — DS-008 Corpus Selection

## 1. Objective
Formally determine which empirically verified MTA candidates from Stage 6.5 Step 2 should be admitted into the expanded DS-008 corpus. The objective is to increase malware-family diversity, capture diversity, TLS version diversity, and JA4 coverage without compromising the scientific integrity of the experimental datasets.

## 2. Existing DS-008 Baseline
The current DS-008 baseline consists of two previously verified, high-quality captures:
- **DS008-C001 (MTA-C037)**: 2025-01-30 — XLoader (TLS 1.2, TLS 1.3, JA4 YES)
- **DS008-C002 (MTA-C046)**: 2024-03-14 — AsyncRAT / XWorm (TLS 1.2, TLS 1.3, JA4 YES)

These remain the anchors of the DS-008 dataset.

## 3. Step 2 Empirical Evidence
The Step 2 empirical verification tested 10 high-priority candidates.
- **Valid PCAPs:** 10/10
- **TLS Handshakes (ClientHello):** 9/10
- **JA4 Computability:** 9/10
- **Bidirectional Flows:** 10/10

One candidate (MTA-C003) failed to produce a valid ClientHello despite containing TLS traffic on port 443, resulting in rejection due to missing JA4 applicability.

## 4. Candidate Evaluation Methodology
Candidates were evaluated strictly on empirical evidence gathered by the `pcap_validator` and `flow_reconstruction` pipeline. Admissions were considered based on:
1. Extractability of complete JA4 fingerprints.
2. Volume of bidirectional TLS flows.
3. Addition of net-new malware families to the corpus.
4. Addition of distinct temporal/delivery mechanisms for existing families.

## 5. Admission Criteria
- **ADMITTED:** Must have JA4 computability. Must either possess high TLS flow volume (HIGH empirical quality) OR add a critical new dimension of diversity (e.g., new malware family, unique loader chain).
- **REJECTED:** No JA4 computability, or low flow volume with highly redundant malware families already covered in the baseline or other admitted candidates.

## 6. Candidate-by-Candidate Decision

### Newly Admitted Samples
- **DS008-C003 (MTA-C006)**: Lumma Stealer + SectopRAT + ArechClient2. **ADMITTED** (HIGH quality, 54 TLS flows, triple-family capture).
- **DS008-C004 (MTA-C015)**: XWorm. **ADMITTED** (MEDIUM quality, 3 TLS flows. Admitted for temporal/delivery diversity as this 2025 email-attachment XWorm contrasts the 2024 DS008-C002 baseline XWorm).
- **DS008-C005 (MTA-C018)**: Lumma Stealer + Ghostsocks/Go Backdoor. **ADMITTED** (HIGH quality, 9 TLS flows. Adds Go-based TLS stack diversity which heavily influences JA4).
- **DS008-C006 (MTA-C021)**: NetSupport RAT + StealC v2. **ADMITTED** (HIGH quality, 7 TLS flows. Three-stage infection chain).
- **DS008-C007 (MTA-C022)**: Lumma Stealer + SectopRAT. **ADMITTED** (HIGH quality, 11 TLS flows. Excellent dual-payload capture).
- **DS008-C008 (MTA-C040)**: GuLoader + Remcos RAT. **ADMITTED** (MEDIUM quality, 3 TLS flows. Admitted because GuLoader adds loader diversity and Remcos adds RAT diversity).
- **DS008-C009 (MTA-C045)**: Pikabot + Meduza Stealer. **ADMITTED** (HIGH quality, 51 TLS flows. Pikabot is a critical Qakbot-replacement loader).
- **DS008-C010 (MTA-C049)**: DarkGate. **ADMITTED** (MEDIUM quality, 4 TLS flows. Admitted because DarkGate is a highly sophisticated, relevant family).

### Tested but Rejected
- **MTA-C003** (Remcos RAT 7.2.5 Pro): **REJECTED**. TLS traffic present but no ClientHello extractable (mid-session capture or non-standard).
- **MTA-C039** (Remcos RAT + XLoader): **REJECTED**. Only 1 TLS flow extracted. XLoader is already well-represented in the baseline (C001), and Remcos RAT is covered by C008 (MTA-C040).

## 7. Malware-Family Diversity
The expanded corpus includes 13 distinct malware families:
XLoader, AsyncRAT, XWorm, Lumma Stealer, SectopRAT, ArechClient2, Ghostsocks (Go Backdoor), NetSupport RAT, StealC v2, GuLoader, Remcos RAT, Pikabot, Meduza Stealer, DarkGate.

**Concentration Warning:** Lumma Stealer is overrepresented in the proposed corpus (appears in 3 distinct captures). This is acceptable given the varying secondary payloads in each capture (SectopRAT, Ghostsocks).

## 8. Temporal Diversity
The expanded corpus spans 2024 to 2026:
- **2026:** 1 capture
- **2025:** 5 captures
- **2024:** 4 captures

## 9. TLS Version Diversity
- **TLS 1.2:** Present in 6/10 admitted captures.
- **TLS 1.3:** Present in 8/10 admitted captures.

## 10. JA4 Coverage
- **EMPIRICALLY VERIFIED:** 100% of the proposed 10-capture corpus has JA4-capable bidirectional TLS flows.

## 11. Proposed Expanded Corpus
The complete, expanded DS-008 corpus:
1. DS008-C001 (XLoader - Baseline)
2. DS008-C002 (AsyncRAT/XWorm - Baseline)
3. DS008-C003 (Lumma/SectopRAT/ArechClient2)
4. DS008-C004 (XWorm)
5. DS008-C005 (Lumma/Ghostsocks)
6. DS008-C006 (NetSupport/StealC v2)
7. DS008-C007 (Lumma/SectopRAT)
8. DS008-C008 (GuLoader/Remcos RAT)
9. DS008-C009 (Pikabot/Meduza Stealer)
10. DS008-C010 (DarkGate)

## 12. Rejected Candidates
- MTA-C003 (Remcos RAT) — No ClientHello.
- MTA-C039 (Remcos RAT + XLoader) — Insufficient flow volume and redundant families.

## 13. Remaining Limitations
The expanded DS-008 corpus remains exclusively MALICIOUS traffic. It does NOT solve the benign-data limitation necessary for ML classification. The existing DS-004 benign validation baseline remains separate and crucial. The expansion purely improves the robustness and diversity of the malicious class.

## 14. Dataset-Source Leakage Implications
All DS-008 samples originate from Malware-Traffic-Analysis.net. Any potential source-specific artifacts (e.g., standard testing environments, specific time-of-day execution) may be present. The experimental ML folds must be explicitly designed to avoid learning these artifacts rather than the actual malware behavior.

## 15. Corpus Expansion Conclusion
The admission of 8 new, highly diverse, JA4-capable captures transforms DS-008 from a minimal 2-PCAP proof-of-concept into a robust 10-PCAP malicious baseline. The inclusion of modern loaders (Pikabot, DarkGate, GuLoader) and Stealers (Lumma, StealC) accurately reflects the 2024-2026 encrypted threat landscape.
