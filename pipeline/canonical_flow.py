"""
Canonical flow contract shared by every ETTH event source and by real-time inference.

Sources: PCAP replay (corpus tables), live capture, and the Zeek / Suricata / eBPF sensor
adapters. Each source emits a flat dict. The same field name must mean the same thing whatever
the source, and a field that a source cannot observe is either absent or None. It is never
zero-filled or guessed. Where a sensor reports something that only looks like an ETTH feature
(negotiated TLS version vs offered version, payload bytes vs IP bytes, FoxIO JA4 vs ETTH JA4),
it is stored under a different name, or tagged with its provenance, so that inference can refuse
it. See docs/integration/CROSS_PHASE_CONTRACTS.md.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import OrderedDict
from typing import Any, Dict, Hashable, Optional, Tuple

# Provenance of flow statistics.
FEATURE_PROVENANCE_ETTH = "ETTH_PACKET_FEATURES"   # pipeline.feature_extraction over per-packet metadata
FEATURE_PROVENANCE_SENSOR = "SENSOR_AGGREGATE"     # counters reported by an external sensor

# JA4 implementations. Models in the registry were trained on ETTH_JA4_V1 values only.
JA4_IMPLEMENTATION_ETTH = "ETTH_JA4_V1"   # pipeline.tls_fingerprinting.generate_ja4 (sorted sig-algs, 'n' for no SNI)
JA4_IMPLEMENTATION_FOXIO = "FOXIO_JA4"    # FoxIO reference (Zeek ja4 package, Suricata >= 7)
JA4_IMPLEMENTATION_V1 = JA4_IMPLEMENTATION_ETTH
JA4_IMPLEMENTATION_V2 = JA4_IMPLEMENTATION_FOXIO
JA4_IMPLEMENTATION_UNKNOWN = "UNKNOWN"
SUPPORTED_JA4_IMPLEMENTATIONS = {JA4_IMPLEMENTATION_ETTH, JA4_IMPLEMENTATION_FOXIO, JA4_IMPLEMENTATION_UNKNOWN}

# Exact versions of ETTH's own fingerprint code. A model records the version it was trained on;
# inference refuses any other version (see backend.inference_engine).
JA4_VERSION_ETTH_V1 = "etth_ja4_v1"                     # historical, non-conformant (corpus v3 'ja4')
JA4_VERSION_FOXIO = "ja4_foxio-c6469a7_etth-2"          # generate_ja4_foxio; 139/139 FoxIO vectors
                                                        # (data/reference/foxio_ja4/vectors.json)

# How the ClientHello bytes behind a fingerprint were obtained.
TLS_HELLO_FIRST_SEGMENT = "FIRST_SEGMENT"               # corpus v3: first segment only, may be truncated
TLS_HELLO_TCP_REASSEMBLY = "TCP_REASSEMBLY"             # pipeline.tls_reassembly, complete Hellos only

# What a byte counter measures.
BYTES_IP_LENGTH = "IP_LENGTH"                  # ETTH offline / live capture, Zeek *_ip_bytes
BYTES_LINK_LAYER = "LINK_LAYER_FRAME"          # Suricata flow counters (captured packet length)
BYTES_TRANSPORT_PAYLOAD = "TRANSPORT_PAYLOAD"  # Zeek orig_bytes / resp_bytes
BYTES_UNKNOWN = "UNKNOWN"
BYTE_SEMANTICS = {BYTES_IP_LENGTH, BYTES_LINK_LAYER, BYTES_TRANSPORT_PAYLOAD, BYTES_UNKNOWN}

SUPPORTED_PROTOCOLS = {"TCP", "UDP"}   # the offline reconstructor only builds TCP and UDP flows
_PLACEHOLDERS = {"", "-", "(empty)", "none", "null", "nan", "missing"}
_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_JA3_STRING = re.compile(r"^\d+,[\d-]*,[\d-]*,[\d-]*,[\d-]*$")
_JA4 = re.compile(r"^[tqd][0-9a-z]{2}[din]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
_PROTO_NUMBERS = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPV6"}

# Fields every canonical flow should carry; the pipeline lists the missing ones as unobserved.
OBSERVABLE_FIELDS = ("forward_endpoint", "reverse_endpoint", "flow_duration", "total_packets", "total_bytes",
                     "packets_per_second", "bytes_per_second")


def is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    return isinstance(value, str) and value.strip().lower() in _PLACEHOLDERS


def clean_str(value: Any) -> Optional[str]:
    return None if is_missing(value) else str(value).strip()


def as_int(value: Any) -> Optional[int]:
    if is_missing(value) or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> Optional[float]:
    if is_missing(value) or isinstance(value, bool):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(out) else out


def protocol_name(value: Any) -> Optional[str]:
    """'tcp' / 6 / 'TCP' -> 'TCP'. Unknown or missing -> None (never defaulted to TCP)."""
    if is_missing(value):
        return None
    if isinstance(value, int) or (isinstance(value, str) and value.strip().isdigit()):
        return _PROTO_NUMBERS.get(int(value), str(int(value)))
    return str(value).strip().upper()


def endpoint(host: Optional[str], port: Optional[int]) -> Optional[str]:
    """Same 'ip:port' convention as pipeline.flow_reconstruction; None unless both parts are known."""
    return f"{host}:{port}" if host and port is not None else None


def normalize_ja3(value: Any = None, ja3_string: Any = None) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Returns (ja3_hash, derivation, rejection_reason).

    The ETTH ja3_hash is the lowercase MD5 hex of the JA3 string. A reported 32-hex value is
    accepted as the hash. A reported JA3 *string* (sometimes placed in a hash field by
    collectors) is hashed with MD5, which is exactly how JA3 defines the hash. Anything else is
    rejected and the hash stays None.
    """
    reason = None
    for candidate in (value, ja3_string):
        s = clean_str(candidate)
        if s is None:
            continue
        if _HEX32.match(s):
            return s.lower(), "REPORTED_HASH", None
        if _JA3_STRING.match(s):
            return hashlib.md5(s.encode()).hexdigest(), "MD5_OF_REPORTED_STRING", None
        reason = reason or "reported JA3 value is neither an MD5 hex digest nor a complete JA3 string"
    return None, None, reason


def normalize_hash32(value: Any) -> Optional[str]:
    """JA3S and similar MD5 fingerprints: lowercase 32-hex or None."""
    s = clean_str(value)
    return s.lower() if s and _HEX32.match(s) else None


def normalize_ja4(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Returns (ja4, rejection_reason). Only syntactically valid JA4 'a_b_c' values are kept."""
    s = clean_str(value)
    if s is None:
        return None, None
    if _JA4.match(s):
        return s, None
    return None, "value is not a JA4 fingerprint (expected a_b_c with 12-hex b and c)"


def tls_version_label(value: Any) -> Optional[str]:
    """'TLSv12' (Zeek), 'TLS 1.2' (Suricata), 771, '0x0303', 1.2 -> '1.2'. Unknown -> None."""
    if is_missing(value):
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value in (1.0, 1.1, 1.2, 1.3):
            return f"{value:.1f}"
        return {0x0300: "SSL3", 0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}.get(int(value))
    s = str(value).strip().upper().replace(" ", "").replace("_", "")
    if s.startswith("0X"):
        try:
            return tls_version_label(int(s, 16))
        except ValueError:
            return None
    table = {"TLSV1": "1.0", "TLSV10": "1.0", "TLSV1.0": "1.0", "TLS1.0": "1.0", "TLSV11": "1.1", "TLSV1.1": "1.1",
             "TLS1.1": "1.1", "TLSV12": "1.2", "TLSV1.2": "1.2", "TLS1.2": "1.2", "TLSV13": "1.3", "TLSV1.3": "1.3",
             "TLS1.3": "1.3", "SSLV3": "SSL3", "1.0": "1.0", "1.1": "1.1", "1.2": "1.2", "1.3": "1.3"}
    return table.get(s)


def count_features(duration: Optional[float], fwd_pkts: Optional[int], rev_pkts: Optional[int],
                   fwd_bytes: Optional[int], rev_bytes: Optional[int]) -> Dict[str, Any]:
    """
    The 15 FLOW_COUNT features computed with the offline formulas
    (pipeline.feature_extraction.extract_flow_level_features). Every feature that depends on
    an unobserved input is None rather than computed from a substituted zero.
    """
    from pipeline.feature_extraction import extract_flow_level_features
    feats = extract_flow_level_features({
        "duration": duration or 0.0, "packet_count": (fwd_pkts or 0) + (rev_pkts or 0),
        "forward_packet_count": fwd_pkts or 0, "reverse_packet_count": rev_pkts or 0,
        "byte_count": (fwd_bytes or 0) + (rev_bytes or 0), "forward_byte_count": fwd_bytes or 0,
        "reverse_byte_count": rev_bytes or 0,
    })
    feats = {k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in feats.items()}
    if duration is None:
        for k in ("flow_duration", "packets_per_second", "bytes_per_second"):
            feats[k] = None
    if fwd_pkts is None or rev_pkts is None:
        for k in ("total_packets", "forward_packets", "reverse_packets", "packets_per_second",
                  "forward_packet_ratio", "reverse_packet_ratio", "packet_count_asymmetry"):
            feats[k] = None
    if fwd_bytes is None or rev_bytes is None:
        for k in ("total_bytes", "forward_bytes", "reverse_bytes", "bytes_per_second",
                  "forward_byte_ratio", "reverse_byte_ratio", "byte_count_asymmetry"):
            feats[k] = None
    return feats


def unobserved_fields(flow: Dict[str, Any]) -> list:
    return [f for f in OBSERVABLE_FIELDS if is_missing(flow.get(f))]


class RecentKeys:
    """Bounded insertion-ordered set used to suppress duplicate sensor records."""

    def __init__(self, maxlen: int = 100_000):
        self.maxlen = maxlen
        self._keys: "OrderedDict[Hashable, None]" = OrderedDict()

    def __contains__(self, key: Hashable) -> bool:
        return key in self._keys

    def add(self, key: Hashable) -> None:
        self._keys[key] = None
        self._keys.move_to_end(key)
        while len(self._keys) > self.maxlen:
            self._keys.popitem(last=False)

    def __len__(self) -> int:
        return len(self._keys)
