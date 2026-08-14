import os
import glob
import json
import hashlib
from scapy.all import rdpcap, TCP, UDP, IP, IPv6

# Minimal JA4 constants
JA4_TLS_EXTENSIONS = {
    0: 'server_name', 1: 'max_fragment_length', 5: 'status_request', 10: 'supported_groups',
    11: 'ec_point_formats', 13: 'signature_algorithms', 16: 'alpn', 43: 'supported_versions',
    45: 'psk_key_exchange_modes', 51: 'key_share'
}

def extract_ja4(client_hello_payload):
    """
    Very minimal JA4 extractor for verification purposes.
    It expects the raw payload of a TLS ClientHello.
    """
    if len(client_hello_payload) < 42:
        return None, "payload_too_short"
        
    try:
        # TLS Record Layer
        content_type = client_hello_payload[0]
        if content_type != 22: # Handshake
            return None, "not_handshake"
            
        # Handshake Type
        handshake_type = client_hello_payload[5]
        if handshake_type != 1: # ClientHello
            return None, "not_client_hello"
            
        pos = 43 # Skip to Session ID length
        session_id_length = client_hello_payload[pos]
        pos += 1 + session_id_length
        
        # Cipher Suites
        cipher_suites_length = int.from_bytes(client_hello_payload[pos:pos+2], 'big')
        pos += 2
        cipher_bytes = client_hello_payload[pos:pos+cipher_suites_length]
        
        ciphers = []
        for i in range(0, len(cipher_bytes), 2):
            val = int.from_bytes(cipher_bytes[i:i+2], 'big')
            # Ignore GREASE
            if (val & 0x0F0F) != 0x0A0A:
                ciphers.append(val)
                
        ciphers.sort()
        cipher_str = ",".join(f"{c:04x}" for c in ciphers)
        
        pos += cipher_suites_length
        
        # Compression Methods
        comp_methods_length = client_hello_payload[pos]
        pos += 1 + comp_methods_length
        
        # Extensions
        extensions_length = int.from_bytes(client_hello_payload[pos:pos+2], 'big')
        pos += 2
        
        extensions = []
        alpn = "00"
        sni = "i" # default no SNI
        has_supported_versions = False
        sig_algs = []
        
        ext_end = pos + extensions_length
        while pos < ext_end:
            ext_type = int.from_bytes(client_hello_payload[pos:pos+2], 'big')
            ext_len = int.from_bytes(client_hello_payload[pos+2:pos+4], 'big')
            pos += 4
            
            # GREASE check
            if (ext_type & 0x0F0F) != 0x0A0A:
                extensions.append(ext_type)
                
            if ext_type == 0: # SNI
                sni = "d" # domain exists
            elif ext_type == 16: # ALPN
                # Extract first ALPN
                alpn_list_len = int.from_bytes(client_hello_payload[pos:pos+2], 'big')
                if alpn_list_len > 0:
                    first_alpn_len = client_hello_payload[pos+2]
                    alpn_str = client_hello_payload[pos+3:pos+3+first_alpn_len].decode('utf-8', 'ignore')
                    if alpn_str:
                        # get first and last char of ALPN
                        alpn = f"{alpn_str[0]}{alpn_str[-1]}"
            elif ext_type == 43: # Supported Versions
                has_supported_versions = True
            elif ext_type == 13: # Signature Algorithms
                sig_len = int.from_bytes(client_hello_payload[pos:pos+2], 'big')
                sig_bytes = client_hello_payload[pos+2:pos+2+sig_len]
                for i in range(0, len(sig_bytes), 2):
                    val = int.from_bytes(sig_bytes[i:i+2], 'big')
                    if (val & 0x0F0F) != 0x0A0A:
                        sig_algs.append(val)
            
            pos += ext_len
            
        extensions.sort()
        sig_algs.sort()
        
        ext_str = ",".join(f"{e:04x}" for e in extensions if e not in [0, 16]) # exclude SNI and ALPN from hash
        sig_str = ",".join(f"{s:04x}" for s in sig_algs)
        
        # Build JA4 Parts
        # protocol, tls_ver, sni, ciphers_count, ext_count, alpn
        tls_ver = "13" if has_supported_versions else "12"
        c_count = f"{len(ciphers):02d}"
        e_count = f"{len(extensions):02d}"
        
        ja4_a = f"t{tls_ver}{sni}{c_count}{e_count}{alpn}"
        ja4_b = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]
        ja4_c = hashlib.sha256(f"{ext_str}_{sig_str}".encode()).hexdigest()[:12]
        
        return f"{ja4_a}_{ja4_b}_{ja4_c}", "success"
        
    except Exception as e:
        return None, str(e)

def verify_pcaps(directory):
    results = []
    
    for pcap_file in glob.glob(os.path.join(directory, "*.pcap")):
        print(f"Analyzing {os.path.basename(pcap_file)}...")
        
        packets = rdpcap(pcap_file)
        
        stats = {
            "file": os.path.basename(pcap_file),
            "total_packets": len(packets),
            "tcp_packets": 0,
            "tls_handshakes": 0,
            "client_hellos": 0,
            "ja4_success": 0,
            "ja4_failures": 0,
            "sample_ja4": []
        }
        
        for pkt in packets:
            if TCP in pkt:
                stats["tcp_packets"] += 1
                payload = bytes(pkt[TCP].payload)
                if len(payload) > 5 and payload[0] == 22 and payload[5] == 1:
                    stats["client_hellos"] += 1
                    ja4, status = extract_ja4(payload)
                    if status == "success":
                        stats["ja4_success"] += 1
                        if len(stats["sample_ja4"]) < 5:
                            stats["sample_ja4"].append(ja4)
                    else:
                        stats["ja4_failures"] += 1
                        
        results.append(stats)
        
    return results

if __name__ == "__main__":
    ds004_dir = "E:/UserBenchmark/encrypted-traffic-threat-hunter/data/samples/ds004"
    if not os.path.exists(ds004_dir):
        print(f"Directory {ds004_dir} not found.")
        exit(1)
        
    out_dir = "E:/UserBenchmark/encrypted-traffic-threat-hunter/data/verification/output"
    os.makedirs(out_dir, exist_ok=True)
    
    results = verify_pcaps(ds004_dir)
    
    out_file = os.path.join(out_dir, "ds004_verification_results.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
        
    print(f"\nVerification complete. Results saved to {out_file}")
    
    for r in results:
        print(f"\n{r['file']}:")
        print(f"  Total Packets: {r['total_packets']}")
        print(f"  TCP Packets: {r['tcp_packets']}")
        print(f"  Client Hellos: {r['client_hellos']}")
        print(f"  JA4 Successes: {r['ja4_success']}")
        print(f"  JA4 Failures: {r['ja4_failures']}")
        if r['sample_ja4']:
            print(f"  Sample JA4: {r['sample_ja4'][0]}")
