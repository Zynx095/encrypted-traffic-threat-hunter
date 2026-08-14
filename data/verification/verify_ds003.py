"""
ETTH Phase 5 Step 8 — DS-003 (USTC-TFC2016) Empirical Verification Script

Purpose: Verify PCAP integrity, protocol distribution, TLS handshake presence,
         JA3/JA4 computability, encrypted flow volume, and leakage inventory.

Environment:
    Python 3.12.0
    scapy 2.7.0
    OS: Windows

This script does NOT train models or perform feature engineering.
It only produces empirical evidence about what the dataset contains.
"""

import json
import hashlib
import os
import sys
import struct
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import (
        PcapReader, TCP, UDP, IP, Raw, conf
    )
    from scapy.layers.tls.handshake import (
        TLSClientHello, TLSServerHello
    )
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.extensions import (
        TLS_Ext_ServerName, TLS_Ext_SupportedVersions,
        TLS_Ext_SignatureAlgorithms, TLS_Ext_SupportedGroups,
        TLS_Ext_ALPN
    )
    SCAPY_TLS = True
except ImportError:
    SCAPY_TLS = False
    from scapy.all import PcapReader, TCP, UDP, IP, Raw, conf

# Suppress scapy warnings
conf.verb = 0

# TLS constants
TLS_CONTENT_TYPE_HANDSHAKE = 22
TLS_HANDSHAKE_CLIENT_HELLO = 1
TLS_HANDSHAKE_SERVER_HELLO = 2

TLS_VERSION_MAP = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# GREASE values to filter out (RFC 8701)
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
    0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
    0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}


def compute_ja3_from_raw(payload):
    """
    Manually parse TLS ClientHello from raw TCP payload and compute JA3 hash.
    Returns (ja3_string, ja3_hash, parsed_fields) or (None, None, None) on failure.
    """
    try:
        if len(payload) < 6:
            return None, None, None

        # Check for TLS record header
        content_type = payload[0]
        if content_type != TLS_CONTENT_TYPE_HANDSHAKE:
            return None, None, None

        tls_version = struct.unpack("!H", payload[1:3])[0]
        record_length = struct.unpack("!H", payload[3:5])[0]

        # Handshake header
        if len(payload) < 9:
            return None, None, None

        handshake_type = payload[5]
        if handshake_type != TLS_HANDSHAKE_CLIENT_HELLO:
            return None, None, None

        # Handshake length (3 bytes)
        hs_length = struct.unpack("!I", b'\x00' + payload[6:9])[0]

        # Client hello body starts at offset 9
        offset = 9

        # ClientHello version
        if len(payload) < offset + 2:
            return None, None, None
        ch_version = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2

        # Random (32 bytes)
        offset += 32
        if len(payload) < offset + 1:
            return None, None, None

        # Session ID
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        if len(payload) < offset + 2:
            return None, None, None

        # Cipher suites
        cipher_suites_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2
        if len(payload) < offset + cipher_suites_len:
            return None, None, None

        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            cs = struct.unpack("!H", payload[offset+i:offset+i+2])[0]
            if cs not in GREASE_VALUES:
                cipher_suites.append(cs)
        offset += cipher_suites_len

        # Compression methods
        if len(payload) < offset + 1:
            return None, None, None
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions
        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        sni_value = None
        alpn_values = []
        sig_algs = []
        supported_versions = []

        if len(payload) > offset + 2:
            ext_total_len = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_total_len

            while offset + 4 <= ext_end and offset + 4 <= len(payload):
                ext_type = struct.unpack("!H", payload[offset:offset+2])[0]
                ext_len = struct.unpack("!H", payload[offset+2:offset+4])[0]
                ext_data = payload[offset+4:offset+4+ext_len]

                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

                # SNI (type 0)
                if ext_type == 0 and len(ext_data) > 5:
                    try:
                        name_len = struct.unpack("!H", ext_data[3:5])[0]
                        sni_value = ext_data[5:5+name_len].decode('ascii', errors='replace')
                    except:
                        pass

                # Supported Groups / Elliptic Curves (type 10)
                if ext_type == 10 and len(ext_data) >= 2:
                    groups_len = struct.unpack("!H", ext_data[0:2])[0]
                    for i in range(2, 2 + groups_len, 2):
                        if i + 2 <= len(ext_data):
                            g = struct.unpack("!H", ext_data[i:i+2])[0]
                            if g not in GREASE_VALUES:
                                elliptic_curves.append(g)

                # EC Point Formats (type 11)
                if ext_type == 11 and len(ext_data) >= 1:
                    fmt_len = ext_data[0]
                    for i in range(1, 1 + fmt_len):
                        if i < len(ext_data):
                            ec_point_formats.append(ext_data[i])

                # Signature Algorithms (type 13)
                if ext_type == 13 and len(ext_data) >= 2:
                    sa_len = struct.unpack("!H", ext_data[0:2])[0]
                    for i in range(2, 2 + sa_len, 2):
                        if i + 2 <= len(ext_data):
                            sa = struct.unpack("!H", ext_data[i:i+2])[0]
                            sig_algs.append(sa)

                # ALPN (type 16)
                if ext_type == 16 and len(ext_data) >= 2:
                    alpn_list_len = struct.unpack("!H", ext_data[0:2])[0]
                    ai = 2
                    while ai < 2 + alpn_list_len and ai < len(ext_data):
                        proto_len = ext_data[ai]
                        ai += 1
                        if ai + proto_len <= len(ext_data):
                            alpn_values.append(ext_data[ai:ai+proto_len].decode('ascii', errors='replace'))
                        ai += proto_len

                # Supported Versions (type 43)
                if ext_type == 43 and len(ext_data) >= 1:
                    sv_len = ext_data[0]
                    for i in range(1, 1 + sv_len, 2):
                        if i + 2 <= len(ext_data):
                            v = struct.unpack("!H", ext_data[i:i+2])[0]
                            if v not in GREASE_VALUES:
                                supported_versions.append(v)

                offset += 4 + ext_len

        # Build JA3 string: TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
        ja3_str = "%d,%s,%s,%s,%s" % (
            ch_version,
            "-".join(str(c) for c in cipher_suites),
            "-".join(str(e) for e in extensions),
            "-".join(str(ec) for ec in elliptic_curves),
            "-".join(str(ep) for ep in ec_point_formats),
        )

        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()

        parsed = {
            "tls_version": TLS_VERSION_MAP.get(ch_version, f"0x{ch_version:04x}"),
            "cipher_suite_count": len(cipher_suites),
            "extension_count": len(extensions),
            "elliptic_curve_count": len(elliptic_curves),
            "ec_point_format_count": len(ec_point_formats),
            "sni": sni_value,
            "alpn": alpn_values,
            "signature_algorithms": len(sig_algs),
            "supported_versions": [TLS_VERSION_MAP.get(v, f"0x{v:04x}") for v in supported_versions],
            "has_grease": any(
                struct.unpack("!H", payload[offset_:offset_+2])[0] in GREASE_VALUES
                for offset_ in range(9, min(len(payload)-1, 50), 2)
                if offset_ + 2 <= len(payload)
            ) if len(payload) > 11 else False,
        }

        return ja3_str, ja3_hash, parsed

    except Exception as e:
        return None, None, None


def parse_server_hello(payload):
    """Parse ServerHello from raw TCP payload. Returns (ja3s_string, ja3s_hash, tls_version) or None."""
    try:
        if len(payload) < 6:
            return None

        content_type = payload[0]
        if content_type != TLS_CONTENT_TYPE_HANDSHAKE:
            return None

        # Handshake type
        if len(payload) < 10:
            return None
        handshake_type = payload[5]
        if handshake_type != TLS_HANDSHAKE_SERVER_HELLO:
            return None

        offset = 9

        # ServerHello version
        if len(payload) < offset + 2:
            return None
        sh_version = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2

        # Random (32 bytes)
        offset += 32

        # Session ID
        if len(payload) < offset + 1:
            return None
        sid_len = payload[offset]
        offset += 1 + sid_len

        # Cipher suite (2 bytes)
        if len(payload) < offset + 2:
            return None
        cipher_suite = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2

        # Compression method (1 byte)
        if len(payload) < offset + 1:
            return None
        offset += 1

        # Extensions
        extensions = []
        if len(payload) > offset + 2:
            ext_len = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_len
            while offset + 4 <= ext_end and offset + 4 <= len(payload):
                ext_type = struct.unpack("!H", payload[offset:offset+2])[0]
                e_len = struct.unpack("!H", payload[offset+2:offset+4])[0]
                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)
                offset += 4 + e_len

        # JA3S: TLSVersion,CipherSuite,Extensions
        ja3s_str = "%d,%d,%s" % (sh_version, cipher_suite, "-".join(str(e) for e in extensions))
        ja3s_hash = hashlib.md5(ja3s_str.encode()).hexdigest()

        return ja3s_str, ja3s_hash, TLS_VERSION_MAP.get(sh_version, f"0x{sh_version:04x}")

    except:
        return None


def is_tls_record(payload):
    """Check if raw TCP payload starts with a TLS record header."""
    if len(payload) < 5:
        return False
    content_type = payload[0]
    version = struct.unpack("!H", payload[1:3])[0]
    return content_type in (20, 21, 22, 23) and version in (0x0300, 0x0301, 0x0302, 0x0303, 0x0304)


def verify_pcap(filepath, label):
    """Verify a single PCAP file and return results dict."""
    results = {
        "file": os.path.basename(filepath),
        "label": label,
        "file_size_bytes": 0,
        "readable": False,
        "total_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "other_packets": 0,
        "tls_packets": 0,
        "plaintext_tcp_packets": 0,
        "flows": {},
        "flow_count": 0,
        "tls_flows": 0,
        "non_tls_flows": 0,
        "client_hellos": 0,
        "server_hellos": 0,
        "ja3_successes": 0,
        "ja3_failures": 0,
        "ja3s_successes": 0,
        "ja3s_failures": 0,
        "ja3_samples": [],
        "ja3s_samples": [],
        "tls_versions_seen": Counter(),
        "cipher_suites_seen": set(),
        "sni_values": [],
        "alpn_values": [],
        "has_sig_algs": False,
        "has_supported_versions": False,
        "src_ips": set(),
        "dst_ips": set(),
        "src_ports": Counter(),
        "dst_ports": Counter(),
        "first_timestamp": None,
        "last_timestamp": None,
        "packet_sizes": [],
    }

    try:
        results["file_size_bytes"] = os.path.getsize(filepath)
    except:
        results["error"] = "File not found"
        return results

    try:
        reader = PcapReader(filepath)
        results["readable"] = True
    except Exception as e:
        results["error"] = f"Cannot read PCAP: {str(e)}"
        return results

    flow_tracker = defaultdict(lambda: {"tls": False, "packet_count": 0, "sizes": []})

    try:
        for pkt in reader:
            results["total_packets"] += 1

            # Timestamp
            ts = float(pkt.time)
            if results["first_timestamp"] is None or ts < results["first_timestamp"]:
                results["first_timestamp"] = ts
            if results["last_timestamp"] is None or ts > results["last_timestamp"]:
                results["last_timestamp"] = ts

            # Packet size
            pkt_len = len(pkt)
            results["packet_sizes"].append(pkt_len)

            if pkt.haslayer(IP):
                ip = pkt[IP]
                results["src_ips"].add(ip.src)
                results["dst_ips"].add(ip.dst)

            if pkt.haslayer(TCP):
                results["tcp_packets"] += 1
                tcp = pkt[TCP]
                results["src_ports"][tcp.sport] += 1
                results["dst_ports"][tcp.dport] += 1

                # Flow key (5-tuple, bidirectional)
                if pkt.haslayer(IP):
                    ip = pkt[IP]
                    fwd = (ip.src, ip.dst, tcp.sport, tcp.dport)
                    rev = (ip.dst, ip.src, tcp.dport, tcp.sport)
                    flow_key = min(fwd, rev)  # canonical
                    flow_tracker[flow_key]["packet_count"] += 1
                    flow_tracker[flow_key]["sizes"].append(pkt_len)

                # Check for TLS
                payload = bytes(tcp.payload) if tcp.payload else b""
                if len(payload) > 5 and is_tls_record(payload):
                    results["tls_packets"] += 1
                    if pkt.haslayer(IP):
                        flow_tracker[flow_key]["tls"] = True

                    # ClientHello
                    if len(payload) > 6 and payload[0] == TLS_CONTENT_TYPE_HANDSHAKE and payload[5] == TLS_HANDSHAKE_CLIENT_HELLO:
                        results["client_hellos"] += 1
                        ja3_str, ja3_hash, parsed = compute_ja3_from_raw(payload)
                        if ja3_hash:
                            results["ja3_successes"] += 1
                            if len(results["ja3_samples"]) < 10:
                                results["ja3_samples"].append({
                                    "ja3_hash": ja3_hash,
                                    "ja3_string": ja3_str[:200],
                                    "tls_version": parsed["tls_version"],
                                    "sni": parsed["sni"],
                                    "cipher_count": parsed["cipher_suite_count"],
                                    "ext_count": parsed["extension_count"],
                                })
                            results["tls_versions_seen"][parsed["tls_version"]] += 1
                            if parsed["sni"]:
                                results["sni_values"].append(parsed["sni"])
                            if parsed["alpn"]:
                                results["alpn_values"].extend(parsed["alpn"])
                            if parsed["signature_algorithms"] > 0:
                                results["has_sig_algs"] = True
                            if parsed["supported_versions"]:
                                results["has_supported_versions"] = True
                                for v in parsed["supported_versions"]:
                                    results["tls_versions_seen"][v + " (supported_versions)"] += 1
                        else:
                            results["ja3_failures"] += 1

                    # ServerHello
                    if len(payload) > 6 and payload[0] == TLS_CONTENT_TYPE_HANDSHAKE and payload[5] == TLS_HANDSHAKE_SERVER_HELLO:
                        results["server_hellos"] += 1
                        sh_result = parse_server_hello(payload)
                        if sh_result:
                            ja3s_str, ja3s_hash, sh_ver = sh_result
                            results["ja3s_successes"] += 1
                            if len(results["ja3s_samples"]) < 5:
                                results["ja3s_samples"].append({
                                    "ja3s_hash": ja3s_hash,
                                    "ja3s_string": ja3s_str[:200],
                                    "tls_version": sh_ver,
                                })
                        else:
                            results["ja3s_failures"] += 1
                else:
                    if len(payload) > 0:
                        results["plaintext_tcp_packets"] += 1

            elif pkt.haslayer(UDP):
                results["udp_packets"] += 1
            else:
                results["other_packets"] += 1

            # Progress reporting
            if results["total_packets"] % 100000 == 0:
                print(f"  Processed {results['total_packets']} packets...", flush=True)

    except Exception as e:
        results["parse_error"] = str(e)

    reader.close()

    # Compute flow statistics
    results["flow_count"] = len(flow_tracker)
    results["tls_flows"] = sum(1 for f in flow_tracker.values() if f["tls"])
    results["non_tls_flows"] = results["flow_count"] - results["tls_flows"]

    # Compute duration
    if results["first_timestamp"] and results["last_timestamp"]:
        results["capture_duration_seconds"] = results["last_timestamp"] - results["first_timestamp"]

    # Convert sets/counters for JSON serialization
    results["unique_src_ips"] = len(results["src_ips"])
    results["unique_dst_ips"] = len(results["dst_ips"])
    results["top_dst_ports"] = dict(results["dst_ports"].most_common(10))
    results["top_src_ports"] = dict(results["src_ports"].most_common(10))
    results["tls_versions_seen"] = dict(results["tls_versions_seen"])
    results["unique_sni_count"] = len(set(results["sni_values"]))
    results["sni_samples"] = list(set(results["sni_values"]))[:10]
    results["alpn_values"] = list(set(results["alpn_values"]))

    # Packet size statistics
    if results["packet_sizes"]:
        sizes = results["packet_sizes"]
        results["packet_size_stats"] = {
            "min": min(sizes),
            "max": max(sizes),
            "mean": sum(sizes) / len(sizes),
            "count": len(sizes),
        }

    # Clean up non-serializable fields
    del results["src_ips"]
    del results["dst_ips"]
    del results["src_ports"]
    del results["dst_ports"]
    del results["cipher_suites_seen"]
    del results["sni_values"]
    del results["flows"]
    del results["packet_sizes"]

    # Encrypted flow percentage
    if results["flow_count"] > 0:
        results["encrypted_flow_pct"] = round(100 * results["tls_flows"] / results["flow_count"], 2)
    else:
        results["encrypted_flow_pct"] = 0

    return results


def main():
    sample_dir = os.path.join(os.path.dirname(__file__), "..", "samples", "ds003")
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    os.makedirs(output_dir, exist_ok=True)

    # Find available PCAP files
    if not os.path.exists(sample_dir):
        print(f"ERROR: Sample directory not found: {sample_dir}")
        print("Please download sample PCAPs to data/samples/ds003/")
        sys.exit(1)

    pcap_files = []
    for f in os.listdir(sample_dir):
        if f.endswith('.pcap') or f.endswith('.pcapng'):
            # Determine label from directory name or file name
            label = "unknown"
            fname_lower = f.lower()
            # DS-003 has 10 benign app names and 10 malware family names
            benign_names = ["bittorrent", "facetime", "ftp", "gmail", "mysql",
                           "outlook", "skype", "smb", "weibo", "worldofwarcraft"]
            malware_names = ["cridex", "geodo", "htbot", "miuref", "neris",
                            "nsis-ay", "shifu", "tinba", "virut", "zeus"]
            for bn in benign_names:
                if bn in fname_lower:
                    label = "benign"
                    break
            for mn in malware_names:
                if mn in fname_lower:
                    label = "malware"
                    break
            pcap_files.append((os.path.join(sample_dir, f), label))

    if not pcap_files:
        print(f"ERROR: No PCAP files found in {sample_dir}")
        sys.exit(1)

    print(f"Found {len(pcap_files)} PCAP file(s) to verify:")
    for fp, lbl in pcap_files:
        print(f"  - {os.path.basename(fp)} ({lbl})")
    print()

    all_results = []
    for filepath, label in pcap_files:
        print(f"Verifying: {os.path.basename(filepath)} ({label})...")
        result = verify_pcap(filepath, label)
        all_results.append(result)

        # Print summary
        print(f"  Readable: {result['readable']}")
        print(f"  Size: {result['file_size_bytes']} bytes")
        print(f"  Total packets: {result['total_packets']}")
        print(f"  TCP: {result['tcp_packets']}, UDP: {result['udp_packets']}, Other: {result['other_packets']}")
        print(f"  TLS packets: {result['tls_packets']}")
        print(f"  Flows: {result['flow_count']} (TLS: {result['tls_flows']}, non-TLS: {result['non_tls_flows']})")
        print(f"  Encrypted flow %: {result.get('encrypted_flow_pct', 'N/A')}%")
        print(f"  ClientHello: {result['client_hellos']}, ServerHello: {result['server_hellos']}")
        print(f"  JA3 success: {result['ja3_successes']}, JA3 fail: {result['ja3_failures']}")
        print(f"  JA3S success: {result['ja3s_successes']}, JA3S fail: {result['ja3s_failures']}")
        print(f"  TLS versions: {result['tls_versions_seen']}")
        print(f"  SNI count: {result['unique_sni_count']}")
        if result.get('capture_duration_seconds'):
            print(f"  Duration: {result['capture_duration_seconds']:.1f}s")
        print()

    # Aggregate summary
    print("=" * 60)
    print("AGGREGATE DS-003 VERIFICATION SUMMARY")
    print("=" * 60)
    total_packets = sum(r["total_packets"] for r in all_results)
    total_tls = sum(r["tls_packets"] for r in all_results)
    total_flows = sum(r["flow_count"] for r in all_results)
    total_tls_flows = sum(r["tls_flows"] for r in all_results)
    total_ch = sum(r["client_hellos"] for r in all_results)
    total_sh = sum(r["server_hellos"] for r in all_results)
    total_ja3 = sum(r["ja3_successes"] for r in all_results)
    total_ja3s = sum(r["ja3s_successes"] for r in all_results)

    print(f"Total packets: {total_packets}")
    print(f"TLS packets: {total_tls} ({100*total_tls/total_packets:.2f}%)" if total_packets > 0 else "")
    print(f"Total flows: {total_flows}")
    print(f"TLS flows: {total_tls_flows} ({100*total_tls_flows/total_flows:.2f}%)" if total_flows > 0 else "")
    print(f"ClientHellos: {total_ch}")
    print(f"ServerHellos: {total_sh}")
    print(f"JA3 extractions: {total_ja3}")
    print(f"JA3S extractions: {total_ja3s}")
    print(f"JA4 computability: {'LIKELY (ClientHello fields present)' if total_ja3 > 0 else 'UNLIKELY (no ClientHello parsed)'}")

    # Save results
    output_file = os.path.join(output_dir, "ds003_verification_results.json")
    with open(output_file, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults saved to: {output_file}")


if __name__ == "__main__":
    main()
