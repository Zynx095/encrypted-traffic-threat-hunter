# Dataset Access Request Drafts

**Date:** 2026-08-15
**Purpose:** Draft formal academic requests for raw PCAP access to the primary ETTH dataset candidates.
**Teacher Help Recommended:** `YES` - Requests originating from or co-signed by a university faculty member are significantly more likely to be approved.

---

## DS-006: Beyond JA4+ Dataset Request

**To:** matousp@fit.vutbr.cz
**Subject:** Academic Dataset Request: Beyond JA4+ Raw PCAPs for Encrypted Traffic Threat Hunter (ETTH) Research

Dear Petr Matoušek and the NES@FIT Research Team,

I am writing to request access to the raw PCAP files for the "Beyond JA4+" dataset referenced in your recent publications. 

I am currently working on an academic research project titled **Encrypted Traffic Threat Hunter (ETTH)**, under university supervision. The objective of our research is to investigate whether combining TLS fingerprint features (specifically JA4 and JA3S) with encrypted-flow behavioral features (such as inter-arrival times and packet lengths) provides a statistically significant improvement in malware detection over using either feature family in isolation.

To conduct this research, we must independently extract both the TLS fingerprint parameters (ClientHello/ServerHello extensions) and the bidirectional flow statistics from the network traffic. While we note that your GitHub repository provides excellent feature extraction scripts and pre-computed datasets, independent extraction from the raw PCAPs is a critical methodological requirement for our experimental pipeline.

**Data Security & Usage Agreement:**
- The data will be used strictly for non-commercial academic research.
- We will NOT attempt to recover or decrypt any payload contents. Our analysis is entirely focused on unencrypted handshake metadata and encrypted flow statistics.
- The raw PCAPs will be stored securely and will NOT be redistributed to any third parties.
- We will appropriately cite your dataset and related papers in any resulting publications.

If there are any formal data sharing agreements or additional institutional verification required, please let us know. A faculty supervisor can co-sign this request if necessary.

Thank you for your time and for your valuable contributions to encrypted traffic analysis.

Sincerely,

[Student Name]
[University Affiliation]
[Faculty Supervisor Name - if applicable]

---

## DS-007: Annotated Encrypted Network Traffic Dataset Request

**To:** Ondřej Ryšavý (via Zenodo Contact / BUT Directory)
**Subject:** Academic Dataset Request: Annotated Encrypted Network Traffic Raw PCAPs (Zenodo 10609384)

Dear Ondřej Ryšavý,

I am writing to formally request access to the raw PCAP files corresponding to the "Annotated Encrypted Network Traffic Dataset for Application, OS, and Malware Identification" hosted on Zenodo.

I am conducting an academic research project, **Encrypted Traffic Threat Hunter (ETTH)**, focused on evaluating the combined efficacy of modern TLS fingerprints (JA4/JA3S) and behavioral flow statistics (packet lengths, timing) in detecting malicious encrypted traffic. 

While the Parquet files publicly available on Zenodo are highly valuable, our specific experimental design requires us to independently parse the raw PCAPs to extract the precise TLS ClientHello extensions required for JA4 computation alongside our custom flow features. Your dataset’s inclusion of both modern SOHO traffic and sandboxed malware makes it an ideal candidate for our primary evaluation.

**Data Security & Usage Agreement:**
- The PCAPs will be used solely for academic research purposes.
- We will not attempt payload decryption or deep packet inspection beyond the unencrypted TLS handshake.
- The data will be stored securely and will not be redistributed.
- All subsequent publications utilizing this data will properly cite your Zenodo record and associated research.

Please let me know if you require a formal institutional letter or a co-signature from my faculty supervisor to authorize this request. 

Thank you for your work in advancing reproducible network security research.

Sincerely,

[Student Name]
[University Affiliation]
[Faculty Supervisor Name - if applicable]
