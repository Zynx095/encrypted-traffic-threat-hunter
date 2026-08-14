# Phase 5: Empirical Verification Report
**Date**: 2026-08-15
**Phase**: 5, Step 8

This report documents the empirical findings from direct inspection of dataset samples, answering the P0 questions identified in the verification queue.

## 1. DS-003 (USTC-TFC2016) Verification Results

**Targeted P0 Questions:**
1. Are JA4 and JA3 fingerprints actually computable from the raw PCAPs?
2. Is there a sufficient volume of encrypted traffic?

**Methodology:**
Representative samples of benign and malware traffic were downloaded from the official GitHub repository and parsed using an independent Python verification script utilizing `scapy`. The JA3 and JA4 extraction process was attempted directly on raw TLS handshake payloads.

**Sample Files Verified:**
1. `Gmail.pcap` (Benign) - 9.5 MB
2. `Zeus.pcap` (Malware) - 14 MB
3. `Tinba.pcap` (Malware) - 2.6 MB

**Empirical Findings:**
*   **Gmail.pcap:** Contained 25,000 packets and 8,629 flows. Of these, 5,106 flows (59.17%) contained TLS records. However, **zero** ClientHello or ServerHello packets were found. The TLS traffic consists entirely of mid-session application data. **JA3/JA4 extraction is impossible.**
*   **Zeus.pcap:** Contained 93,141 packets and 5,780 flows. Only 9 flows (0.16%) were TLS-encrypted. The script extracted 4 ClientHellos and 9 ServerHellos. All handshakes were **SSL 3.0** (version `0x0300`). SSL 3.0 predates modern TLS extensions. **JA3 is computable, but JA4 requires TLS extensions and cannot be reliably extracted from SSL 3.0.**
*   **Tinba.pcap:** Contained 22,000 packets, all UDP (DNS traffic). **Zero TLS packets.**

**Conclusion for DS-003:**
*   **JA4 Computability: NOT SUPPORTED.** The benign traffic sample lacks handshake records entirely, and the malware traffic utilizes obsolete SSL 3.0 without extensions.
*   **Encrypted Flow Volume: INSUFFICIENT.** The malware sample contained only 9 TLS flows out of 5,780 total flows.
*   **Recommendation:** DS-003 should be demoted from Primary Tier 1 for any experiment requiring TLS fingerprinting (JA3/JA4). It may still be partially usable for Flow-only experiments (Experiment A), but its value is severely compromised by the lack of modern encryption.

## 2. DS-004 (CipherSpectrum) Access Verification

**Targeted P0 Question:**
Can this dataset actually be downloaded and does it contain raw PCAPs?

**Empirical Findings:**
*   An official website was located at `https://cspectrum.web.cse.unsw.edu.au`.
*   The site provides open download links for four ZIP files containing raw PCAP data representing 120,000 TLS 1.3 sessions across 40 domains.
*   The data covers the three mandatory/recommended TLS 1.3 cipher suites (`aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`, and a mix).
*   The dataset is licensed under CC BY-NC 4.0.

**Conclusion for DS-004:**
*   **Access: VERIFIED.** The dataset is publicly accessible without requiring formal request or payment.
*   **Recommendation:** Elevate DS-004 to Primary Tier 1 candidate for JA4 + Flow experiments. The next immediate step must be to download a sample and verify JA4 computability on these modern TLS 1.3 PCAPs.

## 3. DS-005 (CSTNET-TLS1.3) Access Verification

**Targeted P0 Question:**
Can this dataset actually be downloaded and does it contain raw PCAPs?

**Empirical Findings:**
*   The dataset is available as part of the ET-BERT project (`linwhitehat/ET-BERT` on GitHub).
*   Due to privacy restrictions, the authors only released an **anonymized version** of the dataset.
*   The provided data is in **.tsv format** (pre-extracted tokens/features), not raw `.pcap`.

**Conclusion for DS-005:**
*   **Access: VERIFIED.**
*   **Format: NOT SUPPORTED.** Because it is TSV-only, it is impossible to run JA4 extraction.
*   **Recommendation:** Reject DS-005 for all fingerprinting experiments.

## 4. DS-004 CipherSpectrum Empirical Verification

**Targeted P0 Question:**
Can JA4 be independently computed from representative raw CipherSpectrum PCAPs containing TLS 1.3 ClientHello messages, and can the resulting traffic also support the required flow-level features?

**Methodology:**
To comply with the constraint of not downloading the entire dataset unnecessarily, a custom Python script was used to read the central directory of the `mix.zip` file (3.5GB) over HTTP via Range requests. 6 representative `.pcap` files were dynamically extracted directly from the web server without downloading the full archive. The samples were verified using an independent `scapy`-based JA4 extraction script (`verify_ds004.py`).

**Empirical Findings:**
*   **Access:** Verified. The Google Form redirects to a public directory (`https://cspectrum.web.cse.unsw.edu.au/cipherspectrum/`) containing the raw ZIP files.
*   **Sample:** 6 PCAPs extracted from `mix.zip` covering different domains (e.g., `slickstream.com`, `outbrain.com`, `coinbase.com`) and browsers.
*   **PCAP Integrity:** All 6 PCAPs parsed successfully. Total packets ranged from 24 to 177 per session.
*   **TLS Findings:** Traffic was definitively TLS 1.3 encrypted (supported_versions extension `43` present).
*   **ClientHello:** 100% of samples contained exactly 1 valid ClientHello.
*   **ServerHello:** 100% of samples contained exactly 1 valid ServerHello.
*   **JA3/JA4:** 100% of samples successfully generated valid JA4 fingerprints (e.g., `t13d1513h2_2c88af3cf3d6_cd53798a7a18`). Modern TLS extensions were correctly parsed.
*   **JA3S/JA4S:** Fully feasible as ServerHellos are present.
*   **Flow Feasibility:** Bidirectional TCP flow is present in all samples (both C->S and S->C packets), enabling extraction of IAT, packet lengths, and flow durations.
*   **Failures:** 0 failures encountered during ClientHello extraction.

**Conclusion for DS-004:**
*   **JA4 Computability: SUPPORTED.** CipherSpectrum provides pristine, modern TLS 1.3 PCAPs that flawlessly parse to JA4 fingerprints and support bidirectional flow analysis.
*   **Recommendation:** DS-004 is officially validated as the primary dataset candidate for JA4 + Flow ETTH experiments.

## Summary of Actionable Next Steps

1.  **Reject DS-003** as the primary dataset for Experiments C (JA4-only) and E (JA4+Flow).
2.  **Reject DS-005** entirely due to lack of PCAPs.
3.  **Prioritize DS-004 (CipherSpectrum)** as the new primary candidate. Initiate verification of a CipherSpectrum PCAP sample to confirm JA4 computability and flow feature extraction.
