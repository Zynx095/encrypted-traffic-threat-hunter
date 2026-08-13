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

**Placeholder:** Summarize the JA3/JA3S specification, extraction methods, and reported accuracy.

### 2.2 JA3 Limitations

**Placeholder:** Document version skew, extension-ordering sensitivity, cipher-suite churn, and false-positive rates.

### 2.3 JA4: Specification and Improvements

**Placeholder:** Summarize the JA4/JA4S specification, TLS 1.3 awareness, ALPN ordering, and extension serialisation changes.

### 2.4 JA3 vs. JA4 Comparison Studies

**Placeholder:** Summarize empirical comparisons, if any.

### 2.5 ECH and Its Impact on Fingerprinting

**Placeholder:** Document what survives ECH (certificate hashes, key shares, ALPN) and what is lost (SNI, extensions).

### 2.6 Alternative Fingerprinting Families

**Placeholder:** Cover ORT, TLSH, packet-level hashing, and any other schemes that do not rely on plaintext ClientHello fields.

### 2.7 Fingerprinting Evasion and Anti-Forensics

**Placeholder:** Summarize active evasion techniques and their effectiveness against passive fingerprinting.

## Evidence Log

<!-- Add per-paper evidence summaries here as the matrix is populated. -->

## Synthesis

<!-- To be written after ≥40 sources are reviewed (timeline gate). -->

## Research Implications

<!-- To be written after synthesis. -->
