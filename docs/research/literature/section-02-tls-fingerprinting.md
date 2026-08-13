# Section 2 — TLS Fingerprinting: JA3 → JA4 → Future

## Objective

Map the evolution of TLS fingerprinting from JA3 through JA4, document limitations and failure modes, assess the impact of ECH, and position JA4 within ETTH's feature set.

## Research Questions

- What does JA3 capture, and where does it fail?
- What improvements does JA4 introduce, and are they empirically validated?
- What is lost under ECH, and what mitigation strategies exist?
- Are alternative fingerprinting families (ORT, TLSH) viable complements or replacements?

## Subsections

### 2.1 JA3: Specification and Empirical Performance

JA3 is the foundational TLS client fingerprinting standard, introduced by Salesforce in 2017. It extracts five fields from the ClientHello packet (SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, Elliptic Curve Formats), concatenates decimal byte values with commas and dashes, and produces a 32-character MD5 hash. GREASE values are filtered out to ensure stability.

**Key properties:**
- Destination-independent: detects applications based on communication patterns rather than destination IP or certificate [althouse2017ja3].
- Widely integrated with Bro/Suricata and threat intelligence feeds (abuse.ch) [althouse2019ja3s].
- Open-sourced under BSD-style license.

### 2.2 JA3 Limitations

Multiple sources document JA3's failure modes:

**A. Collision and instability (supported by multiple papers):**
- Matousek et al. (2021) report that multiple mobile apps share the same JA3 hash due to common libraries or OS sockets. Extension ordering affects fingerprint stability.
- Matousek et al. (2025) show JA3 performs poorly due to random extension ordering creating multiple fingerprints per application.
- Anderson & McGrew (2020) found that 59 of 67 malware JA3 hashes from abuse.ch were also used by benign software—an 88% false-positive overlap.
- The JA4 blog post [althouse2023ja4] explicitly positions JA4 as a replacement due to JA3's MD5 obsolescence and extension-ordering sensitivity.

**B. MD5 obsolescence and maintenance burden:**
- JA3's MD5 hash is already deprecated in TLS 1.3 contexts.
- Blacklist-based approach requires regularly updated fingerprint databases as applications update.

**C. Server-side limitation (JA3S):**
- JA3S has only three fields (Version, Accepted Cipher, List of Extensions), reducing discriminative power compared to JA3 [althouse2019ja3s].

### 2.3 JA4: Specification and Improvements

JA4, introduced by FoxIO in 2023, is a human-readable successor to JA3 with several design improvements:

**Specification details [althouse2023ja4]:**
- Format: `[t|q][version][SNI?d:i][cipher_count][ext_count][alpn] _ [hash_a] _ [hash_b]`
- Protocol marker: `t` for TLS over TCP, `q` for QUIC, `d` for DTLS.
- TLS version: highest value from `supported_versions` extension (ignores GREASE).
- SNI indicator: `d` if SNI present, `i` if absent.
- Cipher count and extension count: 2-digit zero-padded counts after GREASE removal.
- ALPN: first and last characters of first ALPN extension value.
- Hash_a: 12-character truncated SHA-256 of comma-joined hex-sorted cipher list.
- Hash_b: 12-character truncated SHA-256 of hex-sorted extension list + signature algorithms (SNI and ALPN extensions omitted).
- Licensed under BSD-3-Clause for JA4; JA4+ beyond JA4 uses FoxIO License 1.1.

**Design improvements over JA3:**
- Sorting cipher/extension lists before hashing mitigates client-side extension shuffling.
- GREASE values are stripped before counting and hashing.
- Human-readable format aids analyst understanding and explainability.
- Supports QUIC and DTLS in addition to TLS over TCP.

### 2.4 JA3 vs. JA4 Comparison Studies

**One peer-reviewed comparative study exists:**
- Matousek et al. (2025) report that JA4+JA4S achieves >90% accuracy for application identification, while JA3 performs poorly due to random extension ordering causing multiple fingerprints per application. Shared fingerprints across applications reduce discriminative power for both JA3 and JA4.

**Important caveat:** This is a single study with a specific desktop/mobile application set. Independent academic validation of JA4 across diverse environments, TLS versions, and application categories is limited.

### 2.5 ECH and Its Impact on Fingerprinting

**What ECH does [rfc9849]:**
- Encrypts SNI, ALPN, and other sensitive ClientHello fields using HPKE.
- Replaces cleartext ClientHello with Outer ClientHello (dummy info) and encrypted Inner ClientHello.
- Prevents passive on-path observers from learning target domains.

**Operational impact [cisco2025ech]:**
- ECH obscures SNI, replacing it with generic CDN ECH domains.
- Cisco's Encrypted Visibility Engine (EVE) can still fingerprint sessions via Outer ClientHello and TLS handshake characteristics, identifying processes (e.g., Firefox).
- DNS-over-HTTPS further limits visibility.
- ECH adoption was low in observed conference traffic (33 matches at time of documentation).

**Impact on JA3/JA4:**
- JA3 and JA4 both capture SNI presence/absence in their headers, but the actual SNI value is encrypted under ECH.
- Outer ClientHello fields (cipher suites, extensions, JA4-relevant fields) remain visible, but their discriminative power under ECH is not quantified in any source in the corpus.
- Destination-aware fingerprinting (mercury) relies on SNI and IP addresses [anderson2020accurate], which may be unavailable under ECH.

### 2.6 Alternative Fingerprinting Families

**Placeholder:** The corpus does not contain sources evaluating ORT, TLSH, or alternative fingerprinting families. This subsection should be expanded with additional sources if available.

### 2.7 Fingerprinting Evasion and Anti-Forensics

**Known evasion vectors:**
- Extension ordering randomization affects JA3 stability [matousek2025towards, matousek2021reliability].
- Proxy-based attacks can modify flow features to evade detection [martinramos2022cobalt].
- Malware families that actively evolve their TLS usage are more difficult to fingerprint [anderson2016deciphering].

**Anti-forensic considerations:**
- ECH provides privacy against passive observers but also complicates legitimate security controls.
- Adversaries may use JA4-aware fingerprinting to blend with common applications.

## Evidence Log

- althouse2017ja3: JA3 specification; 5 ClientHello fields; MD5 hash; GREASE filtering; destination-independent.
- althouse2019ja3s: JA3S specification; 3 ServerHello fields; combined JA3+JA3S reduces false positives; 55/64 malware hashes shared with benign software.
- althouse2023ja4: JA4 specification; sorted hashes; GREASE-stripped; human-readable; BSD-3-Clause; QUIC/DTLS support.
- matousek2021reliability: JA3 collisions for mobile apps; extension ordering instability; JA3 alone insufficient.
- matousek2025towards: JA4+JA4S >90% accuracy; JA3 poor due to extension ordering; shared fingerprints across apps.
- anderson2020accurate: JA3 collision problem; destination context (mercury) achieves F1 > 0.99; SNI-dependent.
- rfc9849: ECH encrypts SNI/ALPN; Outer ClientHello remains; downgrade resistance required.
- cisco2025ech: ECH operational impact; EVE fingerprinting Outer ClientHello; low observed adoption.

## Synthesis

**Established:**
- JA3 is the foundational TLS client fingerprinting standard, but it is insufficient for reliable identification alone due to collisions, extension-ordering instability, and MD5 obsolescence.
- JA3+JA3S (or JA4+JA4S) reduces false positives by requiring both client and server characteristics to match.
- JA4 introduces design improvements (sorted hashes, GREASE stripping, human-readable format, QUIC/DTLS support) that should improve stability and explainability.

**Uncertain:**
- JA4's empirical collision rates and stability across diverse environments are not independently validated in peer-reviewed literature.
- JA4's performance under ECH is not quantified.
- Whether JA4 consistently outperforms JA3 across all application categories and TLS versions is not established.

## Research Implications

- ETTH should implement JA4 as the primary fingerprinting method but must empirically measure its collision rates and stability in its target environment.
- Dual fingerprinting (JA4+JA4S) should be adopted to reduce false positives, following the JA3+JA3S paradigm.
- ECH resilience must be evaluated: if SNI is unavailable, ETTH must rely on Outer ClientHello fields and behavioral metadata.
- Fingerprint databases require ongoing maintenance as applications and libraries evolve.
