"""
Phase 6 Step 5: TLS Fingerprint Extraction (JA3, JA3S, JA4)
"""
import hashlib
from typing import Dict, Any, Tuple, List, Optional
import struct

def is_grease(val: int) -> bool:
    """Check if a 16-bit value is a GREASE value."""
    return (val & 0x0F0F) == 0x0A0A

def parse_client_hello(payload: bytes) -> Dict[str, Any]:
    """Parse TLS ClientHello and extract fields needed for fingerprinting."""
    if len(payload) < 42:
        return {"error": "payload_too_short"}

    try:
        content_type = payload[0]
        if content_type != 22:
            return {"error": "not_handshake"}

        record_version = int.from_bytes(payload[1:3], 'big')

        handshake_type = payload[5]
        if handshake_type != 1:
            return {"error": "not_client_hello"}

        client_version = int.from_bytes(payload[9:11], 'big')

        pos = 43 # Skip header, random
        session_id_length = payload[pos]
        pos += 1 + session_id_length

        if pos + 2 > len(payload): return {"error": "truncated"}
        cipher_suites_length = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2

        if pos + cipher_suites_length > len(payload): return {"error": "truncated"}
        cipher_bytes = payload[pos:pos+cipher_suites_length]

        ciphers = []
        for i in range(0, len(cipher_bytes), 2):
            val = int.from_bytes(cipher_bytes[i:i+2], 'big')
            ciphers.append(val)

        pos += cipher_suites_length

        if pos >= len(payload): return {"error": "truncated"}
        comp_methods_length = payload[pos]
        pos += 1 + comp_methods_length

        extensions = []
        supported_groups = []
        ec_point_formats = []
        sig_algs = []
        sni_present = False
        alpn_str = ""
        has_supported_versions = False

        if pos + 2 <= len(payload):
            extensions_length = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2

            ext_end = min(pos + extensions_length, len(payload))
            while pos + 4 <= ext_end:
                ext_type = int.from_bytes(payload[pos:pos+2], 'big')
                ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
                pos += 4

                if pos + ext_len > ext_end:
                    break # Truncated extension

                extensions.append(ext_type)

                if ext_type == 0: # SNI
                    sni_present = True
                elif ext_type == 10: # Supported Groups (Elliptic Curves)
                    if ext_len >= 2:
                        sg_len = int.from_bytes(payload[pos:pos+2], 'big')
                        for i in range(0, sg_len, 2):
                            if pos + 2 + i + 2 <= pos + ext_len:
                                val = int.from_bytes(payload[pos+2+i:pos+4+i], 'big')
                                supported_groups.append(val)
                elif ext_type == 11: # EC Point Formats
                    if ext_len >= 1:
                        ecpf_len = payload[pos]
                        for i in range(ecpf_len):
                            if pos + 1 + i < pos + ext_len:
                                ec_point_formats.append(payload[pos+1+i])
                elif ext_type == 13: # Signature Algorithms
                    if ext_len >= 2:
                        sig_len = int.from_bytes(payload[pos:pos+2], 'big')
                        for i in range(0, sig_len, 2):
                            if pos + 2 + i + 2 <= pos + ext_len:
                                val = int.from_bytes(payload[pos+2+i:pos+4+i], 'big')
                                sig_algs.append(val)
                elif ext_type == 16: # ALPN
                    if ext_len >= 2:
                        alpn_list_len = int.from_bytes(payload[pos:pos+2], 'big')
                        if alpn_list_len > 0 and pos + 2 < pos + ext_len:
                            first_alpn_len = payload[pos+2]
                            if pos + 3 + first_alpn_len <= pos + ext_len:
                                alpn_str = payload[pos+3:pos+3+first_alpn_len].decode('utf-8', 'ignore')
                elif ext_type == 43: # Supported Versions
                    has_supported_versions = True

                pos += ext_len

        return {
            "record_version": record_version,
            "client_version": client_version,
            "ciphers": ciphers,
            "extensions": extensions,
            "supported_groups": supported_groups,
            "ec_point_formats": ec_point_formats,
            "sig_algs": sig_algs,
            "sni_present": sni_present,
            "alpn_str": alpn_str,
            "has_supported_versions": has_supported_versions,
            "error": None
        }
    except Exception as e:
        return {"error": str(e)}

def parse_server_hello(payload: bytes) -> Dict[str, Any]:
    """Parse TLS ServerHello and extract fields needed for fingerprinting."""
    if len(payload) < 42:
        return {"error": "payload_too_short"}

    try:
        content_type = payload[0]
        if content_type != 22:
            return {"error": "not_handshake"}

        record_version = int.from_bytes(payload[1:3], 'big')

        handshake_type = payload[5]
        if handshake_type != 2:
            return {"error": "not_server_hello"}

        server_version = int.from_bytes(payload[9:11], 'big')

        pos = 43 # Skip header, random
        session_id_length = payload[pos]
        pos += 1 + session_id_length

        if pos + 2 > len(payload): return {"error": "truncated"}
        cipher_suite = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2

        if pos >= len(payload): return {"error": "truncated"}
        comp_method = payload[pos]
        pos += 1

        extensions = []
        has_supported_versions = False

        if pos + 2 <= len(payload):
            extensions_length = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2

            ext_end = min(pos + extensions_length, len(payload))
            while pos + 4 <= ext_end:
                ext_type = int.from_bytes(payload[pos:pos+2], 'big')
                ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
                pos += 4

                if pos + ext_len > ext_end:
                    break

                extensions.append(ext_type)
                if ext_type == 43:
                    has_supported_versions = True

                pos += ext_len

        return {
            "record_version": record_version,
            "server_version": server_version,
            "cipher_suite": cipher_suite,
            "extensions": extensions,
            "has_supported_versions": has_supported_versions,
            "error": None
        }
    except Exception as e:
        return {"error": str(e)}

def generate_ja3(ch_data: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    if ch_data.get("error"):
        return None, None

    ciphers = [str(c) for c in ch_data["ciphers"] if not is_grease(c)]
    extensions = [str(e) for e in ch_data["extensions"] if not is_grease(e)]
    groups = [str(g) for g in ch_data["supported_groups"] if not is_grease(g)]
    formats = [str(f) for f in ch_data["ec_point_formats"]]

    ja3_string = f"{ch_data['client_version']},{'-'.join(ciphers)},{'-'.join(extensions)},{'-'.join(groups)},{'-'.join(formats)}"
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

    return ja3_string, ja3_hash

def generate_ja3s(sh_data: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    if sh_data.get("error"):
        return None, None

    extensions = [str(e) for e in sh_data["extensions"] if not is_grease(e)]

    ja3s_string = f"{sh_data['server_version']},{sh_data['cipher_suite']},{'-'.join(extensions)}"
    ja3s_hash = hashlib.md5(ja3s_string.encode()).hexdigest()

    return ja3s_string, ja3s_hash

def generate_ja4(ch_data: Dict[str, Any]) -> str:
    if ch_data.get("error"):
        return None

    tls_ver = "13" if ch_data["has_supported_versions"] else "12"
    sni = "d" if ch_data["sni_present"] else "n" # Using n for none, JA4 spec

    ciphers = [c for c in ch_data["ciphers"] if not is_grease(c)]
    extensions = [e for e in ch_data["extensions"] if not is_grease(e)]
    sig_algs = [s for s in ch_data["sig_algs"] if not is_grease(s)]

    c_count = f"{len(ciphers):02d}"
    e_count = f"{len(extensions):02d}"

    alpn_str = ch_data["alpn_str"]
    alpn = f"{alpn_str[0]}{alpn_str[-1]}" if alpn_str else "00"

    ja4_a = f"t{tls_ver}{sni}{c_count}{e_count}{alpn}"

    ciphers.sort()
    cipher_str = ",".join(f"{c:04x}" for c in ciphers)
    ja4_b = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]

    extensions_no_sni_alpn = [e for e in extensions if e not in [0, 16]]
    extensions_no_sni_alpn.sort()
    sig_algs.sort()

    ext_str = ",".join(f"{e:04x}" for e in extensions_no_sni_alpn)
    sig_str = ",".join(f"{s:04x}" for s in sig_algs)

    # Format according to verify_ds004 JA4 minimal implementation
    combined = f"{ext_str}_{sig_str}" if ext_str or sig_str else ""
    if not combined:
         ja4_c = "000000000000"
    else:
         ja4_c = hashlib.sha256(combined.encode()).hexdigest()[:12]

    return f"{ja4_a}_{ja4_b}_{ja4_c}"

def parse_tls_extensions(exts: bytes) -> Tuple[bool, bool, bool, int, bool]:
    """
    Parse a TLS extensions block for compatibility with Phase 6 Step 3 validation tests.
    Extracts presence of SNI, ALPN, Supported Versions, non-GREASE extension count, and TLS 1.3 usage.
    """
    sni = False
    alpn = False
    sv = False
    ext_cnt = 0
    has_tls13 = False

    pos = 0
    ext_len = len(exts)

    while pos + 4 <= ext_len:
        ext_type = int.from_bytes(exts[pos:pos+2], 'big')
        ext_data_len = int.from_bytes(exts[pos+2:pos+4], 'big')
        pos += 4

        if pos + ext_data_len > ext_len:
            break

        if not is_grease(ext_type):
            ext_cnt += 1

            if ext_type == 0:
                sni = True
            elif ext_type == 16:
                alpn = True
            elif ext_type == 43:
                sv = True
                sv_data = exts[pos:pos+ext_data_len]
                if len(sv_data) >= 1:
                    sv_list_len = sv_data[0]
                    sv_pos = 1
                    while sv_pos + 2 <= min(1 + sv_list_len, len(sv_data)):
                        ver = int.from_bytes(sv_data[sv_pos:sv_pos+2], 'big')
                        if ver == 0x0304:
                            has_tls13 = True
                        sv_pos += 2

        pos += ext_data_len

    return sni, alpn, sv, ext_cnt, has_tls13
