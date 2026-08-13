# Citation

John B. Althouse and Laura Lindeman. 2019. "TLS Fingerprinting with JA3 and JA3S." *Salesforce Engineering Blog*. https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/

## Research Problem

JA3 fingerprints the client side of TLS negotiations, but servers reply differently to different clients and consistently to the same client. The problem is whether server-side fingerprinting (JA3S) can complement JA3 to create a more reliable identification of the entire cryptographic negotiation between client and server.

## Objective

To extend JA3 to the server side (JA3S) and demonstrate that combining JA3+JA3S creates a more accurate fingerprint of the TLS session than JA3 alone, reducing false positives in malware detection.

## Methodology

- Defined JA3S using three fields from the ServerHello packet: Version, Accepted Cipher, List of Extensions.
- Concatenated fields using the same comma/dash delimiter scheme as JA3.
- Applied MD5 hashing to produce a 32-character server fingerprint.
- Evaluated combined JA3+JA3S pairs for malware detection and access control.
- Analyzed real-world traffic and abuse.ch JA3 fingerprint feeds.

## Dataset / Data

Not applicable. Technical documentation with illustrative examples from Salesforce operations and abuse.ch threat intelligence feeds.

## Features

- JA3 (client): SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, Elliptic Curve Formats.
- JA3S (server): Version, Accepted Cipher, List of Extensions.

## Models / Algorithms

Not applicable. JA3S is a fingerprinting specification.

## Results

- JA3S fingerprints the server response, which is consistent for the same client but varies across different clients.
- Combined JA3+JA3S creates a fingerprint of the entire cryptographic negotiation between client and server.
- JA3S cannot be used alone for detection or blacklisting; it only holds value when combined with JA3.
- Reverse-engineered 64 of 67 malware fingerprints from abuse.ch; 55 were also used by benign software, highlighting false positive risk of JA3 alone.
- Combined JA3+JA3S reduces false positives compared to JA3 alone.

## Limitations

- JA3S has fewer fields than JA3 (3 vs 5), reducing its discriminative power.
- MD5 hash may become obsolete.
- Blacklist-based approach requires frequent updates.
- Some malware families use standard libraries, making them indistinguishable from benign traffic via JA3+JA3S alone.
- Server responses may vary based on server configuration changes.

## Relevance to ETTH

**Very High.** JA3S is the direct predecessor to JA4S, which ETTH may incorporate. Understanding the client-server fingerprinting paradigm is essential for ETTH's dual-fingerprint approach. The finding that JA3 alone produces false positives (55 of 64 malware fingerprints also used by benign software) directly motivates ETTH's need for multi-signal scoring (fingerprint + behavioral metadata).

## Evidence We Can Use

1. **Client-server pairing:** JA3+JA3S pairs reduce false positives by requiring both client and server characteristics to match.
2. **False positive baseline:** 55/64 (86%) of abuse.ch malware JA3 hashes were also used by benign software, demonstrating JA3's insufficiency for standalone detection.
3. **JA3S field selection:** Version, Accepted Cipher, and List of Extensions are the minimal server-side fields for fingerprinting.
4. **Operational practice:** JA3+JA3S is already deployed in industry (FlowMon, Suricata), providing implementation reference.

## Questions Raised

1. How does JA4+JA4S compare to JA3+JA3S in terms of false positive reduction?
2. Can flow-level behavioral features further reduce the false positives that persist even with JA3+JA3S pairing?
3. How does server-side fingerprinting perform under TLS 1.3 where more handshake fields are encrypted?
