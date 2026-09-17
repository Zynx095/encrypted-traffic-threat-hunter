import csv

# Define all rows as lists
header = ['dataset_id','dataset_name','publication_year','source','official_url','paper_url','raw_pcap','bidirectional_pcap','tls_versions','tls_1_3','quic','clienthello_available','serverhello_available','ja3_available','ja3_computable','ja3s_computable','ja4_available','ja4_computable','flow_features_available','packet_lengths_available','iat_available','benign_traffic','malware_traffic','c2_traffic','label_quality','class_balance','capture_environment','temporal_information','dataset_size','license_or_access','download_status','verification_status','planned_role','suitability','known_leakage','known_limitations','evidence_source','notes']

rows = []


rows.append([
    'DS-001','ISCXVPN2016','2016',
    'University of New Brunswick, Canadian Institute for Cybersecurity (CIC)',
    'https://www.unb.ca/cic/datasets/vpn.html',
    'https://doi.org/10.1109/ICISSP.2016.00033',
    'VERIFIED_YES','NOT_VERIFIED','TLS 1.2 (dominant)','VERIFIED_NO','NOT_APPLICABLE',
    'NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED',
    'VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_NO','NOT_APPLICABLE',
    'PARTIALLY_VERIFIED','PARTIALLY_VERIFIED','PARTIALLY_VERIFIED','VERIFIED_YES',
    '~28 GB PCAP; 158659+ CICFlowMeter samples','Publicly available','PENDING','PARTIALLY_VERIFIED',
    'LEGACY_COMPARISON; FLOW_ONLY_SUPPLEMENT','MEDIUM',
    'IP addresses; SNI; port numbers; flow IDs; timestamps',
    '98.9% unencrypted traffic; deprecated cipher suites (AES-CBC; 3DES; RC4); pre-2018 collection; no malware traffic; class imbalance',
    'dataset-evaluation.md; experimental-design.md; wickramasinghe2025sok',
    'PCAPs available but ClientHello presence and JA4 computability unverified. Suitable for application classification and flow-only baselines but not for malicious/benign detection due to lack of malware labels.'
])

# DS-002
rows.append([
    'DS-002','CIC-Darknet2020','2020',
    'Canadian Institute for Cybersecurity (CIC), University of New Brunswick',
    'https://www.unb.ca/cic/datasets/darknet2020.html',
    'https://doi.org/10.1109/ICCNS.2020.00020',
    'VERIFIED_NO','NOT_APPLICABLE','NOT_APPLICABLE','NOT_APPLICABLE','NOT_APPLICABLE',
    'VERIFIED_NO','VERIFIED_NO','VERIFIED_NO','VERIFIED_NO','VERIFIED_NO','VERIFIED_NO','VERIFIED_NO',
    'VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_NO','NOT_APPLICABLE',
    'PARTIALLY_VERIFIED','VERIFIED_NO','PARTIALLY_VERIFIED','VERIFIED_YES',
    '158659 samples; 73.33 MB CSV','Publicly available','PENDING','PARTIALLY_VERIFIED',
    'FLOW_ONLY_SUPPLEMENT','LOW',
    'IP addresses; destination ports; protocol; flow IDs; timestamps',
    'No raw PCAPs in distribution; extreme class imbalance (~67:1 Tor vs non-Tor); IP/port leakage features; not actual malware traffic; precomputed features only',
    'dataset-evaluation.md; wickramasinghe2025sok',
    'CSV-only distribution prevents JA3/JA4 computation. Can only support Experiment A (Flow-only). Constituent PCAPs exist separately but are not part of this dataset.'
])

# DS-003
rows.append([
    'DS-003','USTC-TFC2016','2016',
    'University of Science and Technology of China (USTC); Institute of Acoustics, Chinese Academy of Sciences',
    'https://github.com/yungshenglu/USTC-TFC2016',
    'https://doi.org/10.1109/ICOIN.2017.00',
    'VERIFIED_YES','NOT_VERIFIED','TLS 1.0; TLS 1.2 (dominant)','VERIFIED_NO','NOT_APPLICABLE',
    'NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED',
    'VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','NOT_VERIFIED',
    'PARTIALLY_VERIFIED','NOT_VERIFIED','PARTIALLY_VERIFIED','VERIFIED_YES',
    '3.71 GB; 20 PCAP files (10 benign; 10 malware)','Publicly available (GitHub)','PENDING','PARTIALLY_VERIFIED',
    'PRIMARY_TRAINING; PRIMARY_TEST','MEDIUM',
    'IP addresses; ports; packet timing artifacts',
    '94.7% unencrypted traffic; deprecated cipher suites; pre-2018 collection; synthetic benign traffic; sandbox-origin malware; class balance after filtering unknown',
    'dataset-evaluation.md; wickramasinghe2025sok; anderson2016deciphering',
    'Strongest candidate for full experimental suite because it combines raw PCAPs with benign and malware traffic. JA4 computability and exact encrypted flow percentage remain unverified.'
])

# DS-004
rows.append([
    'DS-004','CipherSpectrum','2025',
    'Wickramasinghe et al. (IEEE S&P 2025)',
    'NOT_VERIFIED',
    'https://doi.org/10.1109/SP61157.2025.00165',
    'NOT_VERIFIED','NOT_VERIFIED','TLS 1.2; TLS 1.3','VERIFIED_YES','NOT_APPLICABLE',
    'NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED',
    '120000 sessions (reported)','NOT_VERIFIED (may require formal request)','PENDING','NOT_VERIFIED',
    'MODERN_TLS_VALIDATION','PENDING','NOT_VERIFIED',
    'Access conditions unknown; may require formal request; focuses on cipher-agnostic classification; may not cover application-level tasks',
    'wickramasinghe2025sok; dataset-evaluation.md; cross-paper-synthesis.md',
    'Most rigorous modern TLS 1.3 option but access and technical details are unverified. Exists only as a cited reference in existing research; no direct examination performed.'
])

# DS-005
rows.append([
    'DS-005','CSTNET-TLS1.3','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED',
    'TLS 1.3 (exclusive)','VERIFIED_YES','NOT_APPLICABLE',
    'NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED',
    'NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED',
    'PENDING','NOT_VERIFIED','MODERN_TLS_VALIDATION','PENDING','NOT_VERIFIED',
    'Availability unknown; access conditions unverified; no technical details confirmed in existing research',
    'dataset-evaluation.md; wickramasinghe2025sok',
    'Mentioned as potential modern TLS 1.3 dataset. Contains exclusively TLS 1.3 traffic with modern AEAD cipher suites according to existing research. No verified access details or technical specifications available.'
])

# DS-022
rows.append([
    'DS-022','Edge-IIoTset','2022',
    'Guelma University; Annaba University; De Montfort University; Edith Cowan University',
    'https://ieee-dataport.org/documents/edge-iiotset-new-comprehensive-realistic-cyber-security-dataset-iot-and-iiot-applications',
    'https://doi.org/10.1109/ACCESS.2022.3165809',
    'VERIFIED_YES','VERIFIED_YES','NOT_VERIFIED','NOT_VERIFIED','NOT_APPLICABLE',
    'NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED',
    'VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_NO',
    'PARTIALLY_VERIFIED','VERIFIED_YES','PARTIALLY_VERIFIED','VERIFIED_YES',
    '~1.48 GB compressed; 10 normal PCAPs; 13 attack PCAPs; 61 features extracted',
    'Publicly available (IEEE DataPort; Kaggle)','PENDING','PARTIALLY_VERIFIED',
    'IOT_VALIDATION; BENIGN_FALSE_POSITIVE_EVALUATION','MEDIUM',
    'IP addresses; MAC addresses; timestamps; device identifiers',
    'IoT-specific traffic only; no TLS traffic; no malware C2 traffic; attack traffic is synthetic testbed-generated; limited to 10 IoT devices',
    'ferrag2022ieeeAccess; ieee-dataport-edgeiiotset',
    'IoT/IIoT cybersecurity dataset with 10 normal and 13 attack traffic PCAP files. Includes DDoS; MITM; ransomware; backdoor; SQL injection; XSS; port scanning; password attacks; OS fingerprinting. Both PCAP and CSV formats provided. Not suitable for TLS fingerprinting experiments due to lack of TLS traffic.'
])

# DS-023
rows.append([
    'DS-023','CTU-13','2014',
    'CTU University; Czech Republic (Stratosphere IPS)',
    'https://www.stratosphereips.org/datasets-ctu13',
    'https://doi.org/10.1016/j.cose.2014.05.011',
    'VERIFIED_YES','VERIFIED_YES','TLS 1.0; TLS 1.2','VERIFIED_NO','NOT_APPLICABLE',
    'NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED',
    'VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES',
    'PARTIALLY_VERIFIED','PARTIALLY_VERIFIED','VERIFIED_YES','VERIFIED_YES',
    '13 scenarios; ~600 GB total PCAP (botnet only); 1.9 GB dataset download',
    'Publicly available (CC-BY)','PENDING','PARTIALLY_VERIFIED',
    'LEGACY_COMPARISON; PRIMARY_TRAINING','MEDIUM',
    'IP addresses; ports; flow IDs; timestamps',
    '2011 collection; deprecated cipher suites; botnet-only PCAPs available; full traffic PCAPs truncated for privacy; unidirectional NetFlows should not be used; bidirectional NetFlows preferred',
    'garcia2014compsec; stratosphere-ctu13',
    'Classic botnet dataset with 13 malware scenarios. Botnet PCAPs available. Full traffic PCAPs truncated (54 bytes TCP; 42 bytes UDP; 66 bytes ICMP). Bidirectional NetFlows with labels provided. Manual labeling performed. Used in numerous peer-reviewed studies.'
])

# DS-024
rows.append([
    'DS-024','MCFP','2013',
    'Stratosphere IPS; CTU University Czech Republic',
    'https://www.stratosphereips.org/datasets-malware',
    'NOT_VERIFIED',
    'VERIFIED_YES','VERIFIED_YES','NOT_VERIFIED','NOT_VERIFIED','NOT_APPLICABLE',
    'NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED',
    'VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_NO','VERIFIED_YES','VERIFIED_YES',
    'PARTIALLY_VERIFIED','NOT_VERIFIED','PARTIALLY_VERIFIED','VERIFIED_YES',
    'Hundreds of individual captures (varying sizes)',
    'Publicly available (password: infected)','PENDING','PARTIALLY_VERIFIED',
    'PRIMARY_TRAINING; TEMPORAL_DRIFT','MEDIUM',
    'IP addresses; ports; timestamps; malware family identifiers',
    'Long-term captures vary in quality and labeling; some captures are noisy; no standardized feature extraction; password-protected malware zips',
    'stratosphere-mcfp; stratosphere-datasets-overview',
    'Malware Capture Facility Project provides long-term malware captures. Each capture includes original PCAP and password-protected zip with malware binary (password: infected). Hundreds of captures spanning 2013-present. Includes Zeus; Dridex; Emotet; TrickBot; WannaCry; Locky; Tinba; Conficker and many others.'
])

# DS-025
rows.append([
    'DS-025','CIC-DoHBrw-2020','2020',
    'Canadian Institute for Cybersecurity (CIC); University of New Brunswick',
    'https://www.unb.ca/cic/datasets/dohbrw-2020.html',
    'https://doi.org/10.1109/CyberSci.2020.00015',
    'VERIFIED_YES','VERIFIED_YES','TLS 1.2; TLS 1.3','VERIFIED_YES','NOT_APPLICABLE',
    'NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED',
    'VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_NO',
    'PARTIALLY_VERIFIED','VERIFIED_YES','PARTIALLY_VERIFIED','VERIFIED_YES',
    '~10K PCAP files; 28 statistical features per flow',
    'Publicly available (CIC)','PENDING','PARTIALLY_VERIFIED',
    'MODERN_TLS_VALIDATION; TLS13_BENIGN_BASELINE; FLOW_ONLY_SUPPLEMENT','MEDIUM',
    'IP addresses; ports; timestamps; SNI',
    'DoH-specific focus; benign traffic is browser-generated; malicious traffic is DNS tunneling tools (dns2tcp; DNSCat2; Iodine); not traditional malware C2; TLS 1.3 presence verified',
    'montazeri2020dohbrw; cic-dohbrw-2020',
    'Dataset for DNS-over-HTTPS detection. Includes benign DoH (Chrome; Firefox); malicious DoH (tunneling tools); and non-DoH HTTPS traffic. Five browsers/tools; four DoH servers (AdGuard; Cloudflare; Google; Quad9). Raw PCAPs available. TLS 1.3 traffic present.'
])

# DS-026
rows.append([
    'DS-026','CESNET-EncryptedWeb-2021','2022',
    'Masaryk University; Czech Republic',
    'https://www.scidb.cn/en/detail?dataSetId=ec72229d46624e4e8b8528dd0485f5b4',
    'https://doi.org/10.1016/j.dib.2022.108188',
    'VERIFIED_YES','VERIFIED_YES','TLS 1.2','VERIFIED_NO','NOT_APPLICABLE',
    'NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED','NOT_VERIFIED',
    'VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES','VERIFIED_NO','VERIFIED_NO',
    'PARTIALLY_VERIFIED','VERIFIED_YES','VERIFIED_YES','VERIFIED_YES',
    'Seven days; eight servers; 800+ sites; daily PCAP files',
    'Publicly available (Mendeley Data; CC-BY)','PENDING','PARTIALLY_VERIFIED',
    'LEGACY_COMPARISON; BENIGN_FALSE_POSITIVE_EVALUATION','MEDIUM',
    'IP addresses (CryptoPAN anonymized); MAC addresses; SNI; timestamps',
    'TLS 1.2 only; no malware traffic; campus web traffic only; anonymized; no TLS 1.3; no QUIC',
    'spacek2022dib; cesnet-encryptedweb',
    'Real-world campus network encrypted web traffic. Seven days of capture from eight web servers. PCAP files split by day. TLS 1.2 traffic on port 443. Includes matching IIS event logs. IP addresses anonymized with CryptoPAN. Tools and guide for PCAP-to-flow conversion provided.'
])

# Verify all rows have 38 columns
for i, row in enumerate(rows):
    if len(row) != 38:
        print('Row {} ({}) has {} columns'.format(i, row[0], len(row)))
        for j, col in enumerate(row):
            print('  [{}] {}'.format(j, col[:80]))
    else:
        print('Row {} ({}): OK - 38 columns'.format(i, row[0]))

# Write CSV
with open('E:\\UserBenchmark\\encrypted-traffic-threat-hunter\\docs\\research\\dataset-registry.csv', 'w', encoding='utf-8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(header)
    writer.writerows(rows)

print('CSV written successfully.')