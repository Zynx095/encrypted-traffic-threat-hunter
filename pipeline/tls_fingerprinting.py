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
        supported_versions = []
        sni_present = False
        alpn_str = ""
        alpn_first_raw = b""
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
                                alpn_first_raw = bytes(payload[pos+3:pos+3+first_alpn_len])
                                alpn_str = alpn_first_raw.decode('utf-8', 'ignore')
                elif ext_type == 43: # Supported Versions
                    has_supported_versions = True
                    if ext_len >= 3:
                        sv_len = payload[pos]
                        for i in range(0, min(sv_len, ext_len - 1), 2):
                            if pos + 1 + i + 2 <= pos + ext_len:
                                val = int.from_bytes(payload[pos+1+i:pos+3+i], 'big')
                                supported_versions.append(val)
                    elif ext_len == 2:
                        val = int.from_bytes(payload[pos:pos+2], 'big')
                        supported_versions.append(val)

                pos += ext_len

        return {
            "record_version": record_version,
            "client_version": client_version,
            "ciphers": ciphers,
            "extensions": extensions,
            "supported_groups": supported_groups,
            "ec_point_formats": ec_point_formats,
            "sig_algs": sig_algs,
            "supported_versions": supported_versions,
            "sni_present": sni_present,
            "alpn_str": alpn_str,
            "alpn_first_raw": alpn_first_raw,
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

def generate_ja4_v1(ch_data: Dict[str, Any]) -> Optional[str]:
    """
    Generate legacy ETTH JA4 (v1) fingerprint.
    Deviations from FoxIO specification:
    - Sorts signature algorithms.
    - Uses 'n' instead of 'i' for missing SNI.
    - Version is '13' if has_supported_versions else '12'.
    - If no signature algorithms, hashes a trailing '_'.
    - If no ciphers, hashes empty string instead of '000000000000'.
    - Counts above 99 are not capped at 99.
    """
    if not ch_data or ch_data.get("error"):
        return None

    tls_ver = "13" if ch_data.get("has_supported_versions") else "12"
    sni = "d" if ch_data.get("sni_present") else "n" # Using n for none, JA4 legacy

    ciphers = [c for c in ch_data.get("ciphers", []) if not is_grease(c)]
    extensions = [e for e in ch_data.get("extensions", []) if not is_grease(e)]
    sig_algs = [s for s in ch_data.get("sig_algs", []) if not is_grease(s)]

    c_count = f"{len(ciphers):02d}"
    e_count = f"{len(extensions):02d}"

    alpn_str = ch_data.get("alpn_str") or ""
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


_FOXIO_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
                   0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}


def _foxio_alpn(raw: bytes) -> str:
    """First and last character of the first ALPN value, as the FoxIO reference code computes it.

    FoxIO's written spec (technical_details/JA4.md) says non-alphanumeric endpoints are printed as
    hex digits, but both FoxIO reference implementations (rust/ja4/src/tls.rs ``first_last`` and
    python/ja4.py ``first_last_alpn``, commit c6469a7) and their published snapshot
    (tls-non-ascii-alpn.pcapng -> ``99``) substitute '9' for a non-ASCII character. We follow the
    reference implementations so values match FoxIO, Zeek and Suricata tooling.
    """
    if not raw:
        return "00"
    text = raw.decode("utf-8", "replace")
    fix = lambda c: c if ord(c) < 128 else "9"  # noqa: E731
    return fix(text[0]) + fix(text[-1])


def generate_ja4_foxio(ch_data: Dict[str, Any], protocol: str = "t") -> Optional[str]:
    """
    Generate FoxIO-compliant JA4 (v2) fingerprint from parsed ClientHello data.
    Complies with official FoxIO JA4 specification:
    - Protocol character: 't' for TCP, 'q' for QUIC, 'd' for DTLS.
    - TLS version: 2 chars based on highest non-GREASE supported_versions, falling back to client_version.
    - SNI indicator: 'd' if domain SNI present, 'i' if missing / IP.
    - Cipher count: 2 decimal digits capped at 99.
    - Extension count: 2 decimal digits capped at 99 (includes SNI and ALPN if present).
    - ALPN: first and last char of first offered ALPN, or '00' if absent/empty.
    - ja4_b: SHA256[:12] of comma-separated sorted 4-digit hex ciphers (non-GREASE). If none: '000000000000'.
    - ja4_c: SHA256[:12] of comma-separated sorted 4-digit hex extensions (excluding SNI 0 and ALPN 16, non-GREASE)
             plus '_' and comma-separated wire-order 4-digit hex signature algorithms (non-GREASE).
             If no sig_algs extension/empty: ext_str without trailing '_'.
             If no extensions (excluding 0, 16) and no sig_algs: '000000000000'.
    """
    if not ch_data or ch_data.get("error"):
        return None

    # 1. TLS version: highest non-GREASE supported_versions value, else the ClientHello
    #    protocol version; the record-layer version is ignored. Unknown -> "00".
    sv_list = [v for v in ch_data.get("supported_versions", []) if not is_grease(v)]
    if sv_list:
        tls_ver = _FOXIO_VERSIONS.get(max(sv_list), "00")
    else:
        tls_ver = _FOXIO_VERSIONS.get(ch_data.get("client_version"), "00")

    # 2. SNI indicator
    sni = "d" if ch_data.get("sni_present") else "i"

    # 3./4. Non-GREASE cipher and extension counts, capped at 99
    ciphers = [c for c in ch_data.get("ciphers", []) if not is_grease(c)]
    extensions = [e for e in ch_data.get("extensions", []) if not is_grease(e)]
    c_count_str = f"{min(len(ciphers), 99):02d}"
    e_count_str = f"{min(len(extensions), 99):02d}"

    # 5. ALPN: first and last character of the first value; hex digits if either byte is not
    #    ASCII alphanumeric; "00" when absent or empty.
    alpn = _foxio_alpn(ch_data.get("alpn_first_raw")
                       if ch_data.get("alpn_first_raw") is not None
                       else (ch_data.get("alpn_str") or "").encode("utf-8"))

    ja4_a = f"{protocol}{tls_ver}{sni}{c_count_str}{e_count_str}{alpn}"

    # Part B: Ciphers (sorted, 4 hex lowercase)
    if not ciphers:
        ja4_b = "000000000000"
    else:
        sorted_ciphers = sorted(ciphers)
        cipher_str = ",".join(f"{c:04x}" for c in sorted_ciphers)
        ja4_b = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]

    # Part C: Extensions (sorted, excluding SNI 0 and ALPN 16) + Signature Algorithms (wire order)
    exts_no_sni_alpn = sorted([e for e in extensions if e not in (0, 16)])
    ext_str = ",".join(f"{e:04x}" for e in exts_no_sni_alpn)

    # Check if signature_algorithms extension (13) was present
    sig_ext_present = 13 in extensions
    sig_algs = [s for s in ch_data.get("sig_algs", []) if not is_grease(s)]

    if sig_ext_present and sig_algs:
        sig_str = ",".join(f"{s:04x}" for s in sig_algs)  # wire order, NOT sorted
        combined = f"{ext_str}_{sig_str}"
    else:
        combined = ext_str

    if not combined:
        ja4_c = "000000000000"
    else:
        ja4_c = hashlib.sha256(combined.encode()).hexdigest()[:12]

    return f"{ja4_a}_{ja4_b}_{ja4_c}"


generate_ja4_v2 = generate_ja4_foxio


def generate_ja4(ch_data: Dict[str, Any], version: str = "v1_legacy") -> Optional[str]:
    """
    Generate JA4 fingerprint.

    Parameters:
        ch_data: Parsed ClientHello dictionary.
        version: "v1_legacy" (ETTH legacy sorted sig-algs) or "v2_foxio" (FoxIO specification compliant).
    """
    if version in ("v2_foxio", "v2", "foxio", "FOXIO_JA4"):
        return generate_ja4_foxio(ch_data)
    return generate_ja4_v1(ch_data)

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
