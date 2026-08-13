# Citation

John B. Althouse, Jeff Atkinson, Josh Atkins, and Laura Lindeman. 2017. "Open Sourcing JA3." *Salesforce Engineering Blog*. https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41/

## Research Problem

Prior to JA3, TLS client fingerprinting required custom tools and lacked a standardized, shareable format. The problem was to create a simple, platform-agnostic method for profiling SSL/TLS clients that could be integrated with existing network security tools (e.g., Bro, Suricata) and shared via threat intelligence feeds.

## Objective

To define and open-source a standard method (JA3) for creating SSL/TLS client fingerprints from the ClientHello packet, enabling detection of client applications regardless of their destination IP, C2 infrastructure, or SSL certificates.

## Methodology

- Identified five key fields from the TLS ClientHello packet: SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, Elliptic Curve Formats.
- Extracted decimal byte values from these fields and concatenated them with commas (between fields) and dashes (between values).
- Applied MD5 hashing to produce a 32-character fingerprint.
- Implemented GREASE (Generate Random Extensions And Sustain Extensibility) value filtering to ensure stable fingerprints across clients using reserved extension values.
- Released as open-source Python library with Bro/Suricata integration examples.

## Dataset / Data

Not applicable. This is a technical specification/documentation source. No experimental dataset is used.

## Features

- SSL Version (ProtocolVersion)
- Accepted Ciphers (cipher_suites vector)
- List of Extensions (extensions vector)
- Elliptic Curves (supported_groups)
- Elliptic Curve Formats (ec_point_formats)
- GREASE values (filtered out)

## Models / Algorithms

Not applicable. JA3 is a fingerprinting specification, not a machine learning model.

## Results

- JA3 produces a compact 32-character MD5 fingerprint that uniquely identifies TLS client applications.
- Example: Chrome on OSX = `94c485bca29d5392be53f2b8cf7f4304`; Dyre malware = `b386946a5a44d1ddcc843bc75336dfce`.
- JA3 detects applications based on how they communicate rather than what they communicate to, making it resilient to DGA-based domain changes and IP rotation.
- Open-sourced under BSD-style license for broad adoption.

## Limitations

- MD5 hash may become obsolete (already deprecated in TLS 1.3).
- Fingerprint collisions can occur when different applications share the same TLS library or OS socket.
- Blacklist-based approach requires regularly updated fingerprint databases.
- JA3 alone is insufficient for reliable identification (later studies confirm this).
- Does not account for client-side extension ordering randomization introduced in newer browsers.

## Relevance to ETTH

**Very High.** JA3 is the foundational TLS client fingerprinting standard. ETTH's proposed JA4 component builds directly on the JA3 methodology. Understanding JA3's design decisions, limitations, and GREASE handling is essential for implementing and extending TLS fingerprinting in ETTH. The open-source release ensures implementation reference code is available.

## Evidence We Can Use

1. **Field selection rationale:** The five ClientHello fields chosen for JA3 represent the minimal stable set for client identification.
2. **GREASE handling:** JA3 explicitly filters GREASE values, a practice that JA4 inherits.
3. **MD5 choice:** JA3 uses MD5 for compatibility with legacy systems; JA4 moves to SHA-256 truncation for better collision resistance.
4. **Destination independence:** JA3 fingerprints are agnostic to destination, enabling detection regardless of C2 IP/domain changes.

## Questions Raised

1. How does JA3 stability compare to JA4 under browser TLS extension randomization (e.g., Firefox ordering extensions differently)?
2. What is the empirical collision rate of JA3 across a diverse set of real-world applications?
3. How should ETTH handle JA3 fingerprints from applications that dynamically select cipher suites based on server response?
