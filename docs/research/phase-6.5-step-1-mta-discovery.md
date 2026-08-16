# Phase 6.5 Step 1 — Malware-Traffic-Analysis.net Corpus Discovery

## 1. Purpose

This document records the controlled candidate discovery process for expanding the DS-008 (Malware-Traffic-Analysis.net) malicious PCAP corpus before Phase 7 machine-learning experimentation begins.

**Objective:** Identify a candidate pool of high-quality, modern, TLS-relevant malware PCAP captures from the official MTA archive that could expand DS-008 from 2 verified PCAPs into a more diverse and scientifically stronger malicious traffic corpus.

**Scope:** This step produces only a candidate inventory. No PCAPs are downloaded, parsed, or added to the corpus at this stage. All candidates remain in CANDIDATE or REQUIRES_PCAP_VERIFICATION status.

---

## 2. Official Source

**Primary Source:** [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)

The site is maintained by Brad Duncan (Palo Alto Networks Unit 42) and provides:
- Password-protected ZIP archives containing real-world malware PCAPs
- Analysis notes describing malware family, infection chain, and network activity
- Indexed chronologically by year → month → day

No third-party substitutes, mirrors, or derived datasets were used.

---

## 3. Discovery Methodology

1. **Index enumeration:** MTA year-level indexes (2023–2026) were browsed to extract complete entry lists via subagent browsing and targeted web searches.
2. **Keyword filtering:** Entries were filtered for malware families known to use HTTPS/TLS C2 (RATs, stealers, loaders, backdoors). "Scans and probes" server logs, traffic exercises, and phishing-only captures were excluded.
3. **Priority scoring:** Candidates were scored P0–P3 based on recency, TLS relevance, malware-family diversity, and documented C2 type.
4. **Documentation:** All discovered candidates are recorded in `mta-corpus-candidate-registry.csv` with clear distinctions between documented facts and inferred properties.

---

## 4. Year Ranges Searched

| Year | Index URL | Entries Found |
|:-----|:----------|:-------------|
| 2026 | https://www.malware-traffic-analysis.net/2026/index.html | ~37 total entries |
| 2025 | https://www.malware-traffic-analysis.net/2025/index.html | ~50 total entries |
| 2024 | https://www.malware-traffic-analysis.net/2024/index.html | ~57 total entries |
| 2023 | https://www.malware-traffic-analysis.net/2023/index.html | ~105 total entries |

Secondary year ranges (2020–2022) were not searched in Step 1 because 2023–2026 yielded a sufficient candidate pool exceeding the 20-candidate minimum.

---

## 5. Inclusion Criteria

Candidates were selected if they met **at least three** of the following criteria:

1. Malware family is known to use HTTPS/TLS C2 (RAT, stealer, loader, backdoor, botnet)
2. Capture date is 2023 or later (primary) or 2020–2022 (secondary)
3. PCAP file is available for download (password-protected ZIP)
4. MTA page documents an infection chain involving network C2 activity
5. Malware family not already overrepresented in the candidate pool

---

## 6. Exclusion Criteria

The following were excluded:

| Excluded Category | Rationale |
|:-----------------|:----------|
| "Scans and probes" server log captures | No malware C2; purely background traffic |
| Traffic analysis exercises (without separate real traffic PCAP) | Exercise traffic only; not real infections |
| Phishing email / fake login page captures | No malware C2 channel to fingerprint |
| DNS-only captures | No TLS; no JA3/JA4 extractable |
| HTTP-only malware | TLS absent; not relevant to TLS fingerprint research |
| "30 Days of Formbook" series (June–July 2023, Days 1–30) | 30 near-identical Formbook/XLoader single-day captures; extremely redundant; one representative entry added if needed |
| AgentTesla SMTP/FTP exfil captures | AgentTesla uses FTP/SMTP not HTTPS; TLS not applicable |
| Astaroth/Guildma Brazil captures | Uses COM-based LOLBins; limited HTTPS C2 relevance |

---

## 7. Priority Methodology

| Priority | Criteria |
|:---------|:---------|
| **P0** | Recent (2024–2026), downloadable PCAP, family known to use HTTPS/TLS C2, adds new family or strong temporal diversity |
| **P1** | Recent (2023–2026), PCAP likely available, HTTPS/TLS inferred but not explicitly documented, or adds temporal diversity within an existing family |
| **P2** | Older TLS-relevant capture or duplicate family with lower certainty; requires additional justification |
| **P3 / LEGACY_CANDIDATE** | Pre-2023 or uncertain TLS relevance; significant empirical verification required |
| **REJECT** | No meaningful encrypted malware C2; server scans; exercises; FTP/SMTP exfil only |
| **ALREADY_VERIFIED** | Already part of DS-008 verified baseline |

---

## 8. Candidate Count Summary

| Status | Count |
|:-------|------:|
| P0 candidates | 16 |
| P1 candidates | 21 |
| P2 candidates | 8 |
| LEGACY_CANDIDATE | 2 |
| ALREADY_VERIFIED | 2 |
| **Total discovered** | **49** |

Two entries (MTA-C037, MTA-C046) are already verified as DS-008 baseline PCAPs (PCAP-1 and PCAP-2) and are listed for registry completeness only.

---

## 9. Malware-Family Diversity

| Malware Family | Category | Candidates |
|:--------------|:---------|:----------|
| Lumma Stealer | Stealer | MTA-C002, C011, C018, C020, C023, C025, C027, C028, C035, C038, C041 |
| XWorm | RAT | MTA-C015 (2025), MTA-C046 (VERIFIED) |
| XLoader / Formbook | Stealer/Loader | MTA-C007, C019, C024, C037 (VERIFIED) |
| Remcos RAT | RAT | MTA-C003, C008, C010, C033, C039 |
| NetSupport RAT | RAT | MTA-C005, C012, C021, C029, C032, C034 |
| StealC / StealC v2 | Stealer | MTA-C013, C021, C029, C032, C034, C051 |
| AsyncRAT | RAT | MTA-C031, C047, C052 |
| DarkGate | Loader/Backdoor | MTA-C049, C050 |
| Pikabot | Loader | MTA-C045, C048 |
| Latrodectus | Loader | MTA-C042, C044 |
| SectopRAT / ArechClient2 | RAT | MTA-C006, C022, C025 |
| GuLoader | Loader | MTA-C040 |
| Koi Loader/Stealer | Loader/Stealer | MTA-C026 |
| Ghostsocks / Go Backdoor | Backdoor | MTA-C018 |
| Cobalt Strike | C2 Framework | MTA-C043 |
| Rhadamanthys | Stealer | MTA-C017 |
| PureLogs | Stealer | MTA-C030 |
| StrelaStealer | Stealer | MTA-C036 |
| SocGholish | Loader | MTA-C047 |
| MintsLoader / GhostWeaver RAT | Loader/RAT | MTA-C009 |
| Rsockstun | Proxy | MTA-C027, C028 |
| SSLoad | Loader | MTA-C043 |
| RedLine Stealer | Stealer | MTA-C053 |
| IcedID / Bokbot | Loader/Banker | MTA-C054 |
| MacSync Stealer | Stealer/macOS | MTA-C014 |

---

## 10. Year Distribution of Candidates

| Year | Candidates | Notes |
|:-----|:----------:|:------|
| 2026 | 10 | Very recent; excellent JA4 relevance |
| 2025 | 27 | Largest group; high TLS 1.3 prevalence expected |
| 2024 | 15 | Moderate; includes Pikabot, DarkGate, Latrodectus |
| 2023 | 4 | Lower priority; supplemental diversity only |

---

## 11. Top 10 Recommended Candidates for Step 2

These candidates are recommended for priority PCAP download and empirical verification in Step 2, based on highest expected scientific value (family diversity, TLS relevance, recency):

| Rank | ID | Date | Family | Reason |
|:----:|:---|:-----|:-------|:-------|
| 1 | MTA-C018 | 2025-09-24 | Lumma Stealer + Ghostsocks/Go Backdoor | Go TLS stack produces distinctive JA4; multi-family diversity |
| 2 | MTA-C006 | 2026-04-16 | Lumma + SectopRAT + ArechClient2 | Triple-family; maximum fingerprint diversity per capture |
| 3 | MTA-C021 | 2025-08-20 | SmartApeSG + NetSupport RAT + StealC v2 | Three-stage infection; three distinct TLS fingerprint sources |
| 4 | MTA-C040 | 2024-08-26 | GuLoader + Remcos RAT | Loader + RAT multi-stage; distinct TLS fingerprints per stage |
| 5 | MTA-C045 | 2024-03-06 | Pikabot + Meduza Stealer | Pikabot is a Qakbot replacement; adds new sophisticated loader class |
| 6 | MTA-C049 | 2024-01-30 | DarkGate | Sophisticated HTTPS-C2 loader; completely new family for corpus |
| 7 | MTA-C003 | 2026-08-06 | Remcos RAT 7.2.5 Pro | Most recent Remcos; version 7 implies modern TLS stack |
| 8 | MTA-C039 | 2024-09-11 | Remcos RAT + XLoader | Dual-family data dump; Remcos adds to corpus; XLoader complements baseline |
| 9 | MTA-C022 | 2025-08-15 | Lumma Stealer + SectopRAT | Dual-payload; SectopRAT distinct fingerprint profile |
| 10 | MTA-C015 | 2025-11-19 | XWorm | 2025 XWorm with email delivery; temporal companion to DS-008 PCAP-2 |

---

## 12. Explicitly Documented HTTPS/TLS Properties

MTA entry pages viewed during this discovery step did not contain explicit TLS version documentation in their notes sections (the notes files are inside password-protected ZIP archives). Therefore:

- **Documented by MTA as TLS/HTTPS:** 0 candidates have explicit protocol documentation visible from the index/notes page HTML
- **HTTPS/TLS inferred from malware family behavior:** 47 candidates (based on known C2 protocols for each family)
- **TLS version documented:** 0 (requires PCAP empirical verification)
- **Unknown/uncertain protocol:** 2 candidates (MTA-C053 RedLine, MTA-C014 MacSync)

This is consistent with MTA's format: detailed technical notes are inside the ZIP archives, not visible from index pages.

---

## 13. Unknown Properties Requiring Empirical Verification

The following properties are **UNKNOWN** for all candidates and must be determined during Step 2 PCAP download and parsing:

- Actual PCAP filename(s) within the ZIP archive
- PCAP file size
- TLS version (TLS 1.2 vs TLS 1.3)
- Number of flows with ClientHello
- JA3 / JA3S / JA4 computability
- Number of usable bidirectional flows
- Whether multiple PCAPs are present per archive
- Password scheme (MTA notes a "new password scheme" effective 2026-08-12)

---

## 14. Limitations

1. **No empirical PCAP parsing:** All TLS and protocol properties are inferred from malware-family knowledge, not from actual PCAP analysis. Every candidate is marked `REQUIRES_PCAP_VERIFICATION`.
2. **Filename uncertainty:** PCAP filenames within ZIP archives follow MTA naming conventions but cannot be confirmed without downloading. Filenames in the registry marked UNKNOWN are inferred from conventions.
3. **MTA page truncation:** Individual entry HTML pages were truncated in browser tools; detailed notes were inaccessible without ZIP extraction.
4. **Password scheme change:** MTA announced a new password scheme effective 2026-08-12. The current password must be verified from the "About" page before Step 2 downloads.
5. **"Possible" qualifiers:** Several candidates (MTA-C017 Rhadamanthys, MTA-C031 AsyncRAT) are labeled "possible" by MTA. Their identities must be confirmed empirically.
6. **30 Days of Formbook:** The June–July 2023 Formbook series was excluded from the candidate pool due to extreme redundancy. A representative subset could be included if additional XLoader/Formbook diversity is needed.

---

## 15. Recommended Step 2 Action

**Stage 6.5 Step 2 — Targeted PCAP Download and Empirical Verification**

Priority order for Step 2:
1. Download and parse the top 10 recommended candidates listed in Section 11
2. Run empirical PCAP validation using the existing Phase 6 pipeline (`pipeline/pcap_validator.py`, `pipeline/flow_reconstruction.py`, `pipeline/tls_fingerprinting.py`)
3. Report actual TLS version, flow counts, JA3/JA3S/JA4 computability for each downloaded PCAP
4. Reject any PCAP where no usable TLS ClientHello is found after full parse
5. Update `mta-corpus-candidate-registry.csv` status from CANDIDATE to either VERIFIED or REJECTED_PCAP_VERIFICATION
6. Update the dataset manifest with newly verified PCAPs

**Prerequisites for Step 2:**
- Verify current MTA password from the "About" page (new scheme as of 2026-08-12)
- Confirm available disk space (MTA ZIP files are typically 10–50 MB each)
- Use isolated environment for extraction of malware-adjacent PCAP files
- Do not modify existing DS-008 verified PCAPs or any Phase 6 processed outputs

---

*Audit note: All facts in this document are sourced from MTA index pages and published search results. No PCAP files were downloaded during Step 1. Properties marked DOCUMENTED BY MTA are derived from MTA entry titles and indexed page content. Properties marked INFERRED are based on known malware-family behavior from public threat intelligence. Properties marked NOT YET VERIFIED require empirical PCAP analysis.*
