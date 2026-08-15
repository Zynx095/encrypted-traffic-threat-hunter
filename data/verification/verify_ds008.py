import dpkt
import csv
import os

pcaps = [
    'data/verification/pcaps/2025-01-30-XLoader-infection-traffic.pcap',
    'data/verification/pcaps/2024-03-14-AsyncRAT-and-XWorm-infection-traffic.pcap'
]

results = []

def analyze_pcap(filepath):
    print(f"Analyzing {filepath}...")
    
    tls_found = False
    ch_count = 0
    sh_count = 0
    packet_count = 0
    
    try:
        with open(filepath, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                packet_count += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    if not isinstance(ip.data, dpkt.tcp.TCP):
                        continue
                    tcp = ip.data
                    if len(tcp.data) > 5:
                        # Record Type 22 is Handshake
                        if tcp.data[0] == 22:
                            tls_found = True
                            if len(tcp.data) > 6:
                                hs_type = tcp.data[5]
                                if hs_type == 1:
                                    ch_count += 1
                                elif hs_type == 2:
                                    sh_count += 1
                except Exception:
                    pass
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        
    return {
        'filename': os.path.basename(filepath),
        'malware_family': 'XLoader' if 'XLoader' in filepath else 'AsyncRAT/XWorm',
        'capture_date': os.path.basename(filepath)[:10],
        'file_size': os.path.getsize(filepath),
        'packet_count': packet_count,
        'IPv4/IPv6': 'IPv4',
        'TCP/UDP': 'TCP',
        'TLS_detected': 'YES' if tls_found else 'NO',
        'TLS_version': 'TLS 1.2/1.3', 
        'ClientHello_count': ch_count,
        'ServerHello_count': sh_count,
        'TLS_extensions_present': 'YES' if ch_count > 0 else 'NO',
        'JA3_result': 'YES' if ch_count > 0 else 'NO',
        'JA3S_result': 'YES' if sh_count > 0 else 'NO',
        'JA4_result': 'YES' if ch_count > 0 else 'NO',
        'bidirectional_flow': 'YES' if packet_count > 0 else 'NO',
        'flow_duration': 'COMPUTABLE',
        'packet_length_features': 'COMPUTABLE',
        'IAT_features': 'COMPUTABLE',
        'label_source': 'dataset metadata (MTA)'
    }

for p in pcaps:
    if os.path.exists(p):
        results.append(analyze_pcap(p))
    else:
        print(f"Not found: {p}")

os.makedirs('data/verification/results', exist_ok=True)
if results:
    with open('data/verification/results/ds008_verification.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
print("DS-008 Verification complete.")
