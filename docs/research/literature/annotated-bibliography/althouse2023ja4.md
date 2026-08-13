# Citation

John Althouse. 2023. "JA4+ Network Fingerprinting." *FoxIO Blog*. https://blog.foxio.io/ja4-network-fingerprinting-9376fe9ca637

## Research Problem

JA3 has limitations: opaque MD5 hashes, vulnerability to extension ordering randomization, and lack of support for modern protocols (QUIC, DTLS). The problem is to create a next-generation fingerprinting standard that is human-readable, resilient to client-side shuffling, and extensible to multiple protocols.

## Objective

To introduce JA4, a human-readable TLS client fingerprinting standard, and JA4+, a suite of modular network fingerprints for multiple protocols (TLS, QUIC, SSH, TCP, DHCP, etc.).

## Methodology

- Designed JA4 format: `[t|q][version][SNI?d:i][cipher_count][ext_count][alpn] _ [hash_a] _ [hash_b]`
- Protocol marker: `t` for TLS over TCP, `q` for QUIC, `d` for DTLS.
- TLS version: highest value from `supported_versions` extension (ignores GREASE).
- SNI indicator: `d` if SNI present, `i` if absent (IP-based destination).
- Cipher count and extension count: 2-digit zero-padded counts after GREASE removal.
- ALPN: first and last characters of first ALPN extension value (or `00` if none).
- Hash_a: 12-character truncated SHA-256 of comma-joined hex-sorted cipher list.
- Hash_b: 12-character truncated SHA-256 of hex-sorted extension list + signature algorithms (SNI and ALPN extensions omitted).
- Extended to JA4S (server), JA4H (HTTP), JA4L (latency), JA4X (X509), JA4SSH, JA4TCP, JA4D (DHCP).

## Dataset / Data

Not applicable. Technical specification with illustrative examples.

## Features

- TLS version (from `supported_versions` or ProtocolVersion).
- SNI presence/absence.
- Cipher suite list (sorted, GREASE-removed).
- Extension list (sorted, GREASE-removed, SNI/ALPN omitted from hash).
- Signature algorithms (appended to extension list for hash_b).
- ALPN first/last characters.

## Models / Algorithms

Not applicable. JA4 is a fingerprinting specification.

## Results

- JA4 produces human-readable fingerprints (e.g., `t13d1516h2_8daaf6152771_b186095e22b6`) instead of opaque MD5 hashes.
- Sorting cipher/extension lists before hashing makes JA4 resilient to client-side extension shuffling.
- GREASE values are stripped before counting and hashing.
- JA4 covers QUIC (`q`) and DTLS (`d`) in addition to TLS over TCP (`t`).
- JA4 is BSD-3-Clause licensed, enabling immediate adoption from JA3.
- JA4+ beyond JA4 is licensed under FoxIO License 1.1 (non-permissive for monetization).

## Limitations

- Community fingerprint database still under development (not yet publicly available at time of writing).
- Limited independent academic validation of JA4 collision rates and stability.
- Adoption not yet widespread compared to JA3.
- Some JA4+ methods (JA4S, JA4L, etc.) are under restrictive licensing for commercial use.
- Browser extension ordering randomization may still affect fingerprint stability in edge cases.

## Relevance to ETTH

**Very High.** JA4 is the core fingerprinting method proposed for ETTH. Understanding its exact specification, GREASE handling, sorting behavior, and hash construction is essential for correct implementation. The human-readable format also aids explainability to security analysts. The licensing terms (BSD-3-Clause for JA4) are favorable for academic/internal use.

## Evidence We Can Use

1. **JA4 format specification:** Exact algorithm for constructing JA4 fingerprints from ClientHello packets.
2. **GREASE handling:** JA4 strips GREASE values before counting and hashing, ensuring stability.
3. **Sorting behavior:** Cipher and extension lists are sorted before hashing, mitigating client-side randomization.
4. **Protocol coverage:** JA4 handles TLS, QUIC, and DTLS via protocol marker.
5. **SNI/ALPN handling:** SNI and ALPN are captured in the header but excluded from hash_b to ensure consistent hashing regardless of destination.

## Questions Raised

1. What is the empirical collision rate of JA4 across a large, diverse set of real-world applications?
2. How does JA4 perform compared to JA3 in longitudinal studies as applications update?
3. Can JA4 fingerprints be combined with destination context (as in mercury) for further disambiguation?
4. How does ECH affect the availability of JA4 input fields (SNI, ALPN)?
