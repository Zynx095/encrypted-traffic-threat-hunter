# Phase 7 Step 6: Independent Benign Data Acquisition Status

**STATUS = BLOCKED_PENDING_HUMAN_PROVISIONING**

## 1. Objective
Identify and verify independently sourced benign datasets to resolve the severe class imbalance (424:1) and DS-004 vs. DS-008 source confounding present in the Encrypted Traffic Threat Hunter (ETTH) experimental dataset.

## 2. Current Status
Following a forensic search of the repository (`data/verification/pcaps/`, `data/interim/`, `data/processed/`, etc.), **no independent benign raw PCAP data was found**. The automated acquisition was previously blocked (Phase 7 Step 4) due to academic registration requirements, licensing acceptance, and access controls that must not be bypassed automatically.

Therefore, the pipeline is blocked pending manual human provisioning.

## 3. Human Provisioning Requirements
The human researcher must manually acquire one of the following high-priority benign candidates and place the raw `.pcap` or `.pcapng` (or their `.zip` archives) into `data/verification/pcaps/`.

Prioritization is based on the dataset's ability to introduce modern benign TLS traffic (TLS 1.2/1.3) to resolve source-confounding against the heavily TLS-laden MTA malicious corpus.

### Priority 0 Candidate: CIRA-CIC-DoHBrw-2020
- **Dataset ID**: CAND-008
- **Source**: Canadian Institute for Cybersecurity (UNB)
- **Expected Traffic Type**: Modern TLS 1.2/1.3 benign browsing behavior and DNS-over-HTTPS tunnels.
- **Expected PCAP Format**: `.pcap`
- **Expected TLS Relevance**: Extremely High
- **Expected JA3/JA3S/JA4 Relevance**: High
- **Access Requirements**: Academic license acceptance and registration form required.
- **Expected Local Destination**: `data/verification/pcaps/CIRA-CIC-DoHBrw-2020/` (or similar directory)
- **Step 4 Verification Test**: The verification pipeline will evaluate flow counts, modern TLS (v1.2/1.3) availability, client/server hello presence, and structural differences against the MTA corpus to quantify source confounding.

### Priority 1 Candidate: CIC-IDS-2017
- **Dataset ID**: CAND-006
- **Source**: Canadian Institute for Cybersecurity (UNB)
- **Expected Traffic Type**: Mixed (Benign background traffic with attacks)
- **Expected PCAP Format**: `.pcap`
- **Expected TLS Relevance**: High (TLS 1.2 present)
- **Expected JA3/JA3S/JA4 Relevance**: High
- **Access Requirements**: Academic license acceptance and registration form required.
- **Expected Local Destination**: `data/verification/pcaps/CIC-IDS-2017/`
- **Step 4 Verification Test**: Will test if the benign-labeled traffic produces viable TLS fingerprints and flows to balance out the 424:1 malicious disparity.

### Priority 1 Candidate: CIC-Bell-DNS-EXF-2021
- **Dataset ID**: CAND-007
- **Source**: Canadian Institute for Cybersecurity (UNB)
- **Expected Traffic Type**: Mixed (Benign modern baseline with DNS exfiltration)
- **Expected PCAP Format**: `.pcap`
- **Expected TLS Relevance**: High
- **Expected JA3/JA3S/JA4 Relevance**: High
- **Access Requirements**: Academic license acceptance and registration form required.
- **Expected Local Destination**: `data/verification/pcaps/CIC-Bell-DNS-EXF-2021/`

## 4. Next Steps for Human Researcher
1. Go to the URL provided in `docs/research/custom-dataset-candidate-registry.csv` for the selected dataset.
2. Complete the registration/access form to obtain the download link.
3. Download the PCAP data.
4. Place the raw PCAP files or ZIP archives into `data/verification/pcaps/`.
5. Trigger the next step to run empirical verification on the newly provisioned data.
