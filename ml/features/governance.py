"""
Feature governance registry and track schemas.

The five canonical tracks keep the exact meaning they had in the Phase 6 experiment
constructor (pipeline/experimental_dataset_constructor.py):

    A_FLOW      flow behavioural statistics + TLS structural metadata, all flows
    B_JA3       JA3 hash only,                       flows with a JA3
    C_JA4       JA4 only,                            flows with a JA4
    D_JA3_FLOW  JA3 + flow statistics + TLS structural, flows with a JA3
    E_JA4_FLOW  JA4 + flow statistics + TLS structural, flows with a JA4

Additional, explicitly non-canonical feature sets exist for ablation and diagnostics and are
never reported as one of A-E.

Model matrices are built from an ALLOW-list: a column must be registered here with a
model-eligible family to reach a model. Unknown columns are rejected, which is stronger than
a deny-list because new provenance columns cannot leak in by accident.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional, Sequence

SCHEMA_VERSION = "9.0.0"

_STAT_SUFFIXES = ["mean", "median", "std", "min", "max", "p25", "p75", "p90", "p95"]

FLOW_COUNT_FEATURES = [
    "flow_duration", "total_packets", "total_bytes", "forward_packets", "reverse_packets",
    "forward_bytes", "reverse_bytes", "packets_per_second", "bytes_per_second",
    "forward_packet_ratio", "reverse_packet_ratio", "forward_byte_ratio", "reverse_byte_ratio",
    "packet_count_asymmetry", "byte_count_asymmetry",
]
PACKET_LENGTH_FEATURES = [f"{p}_{s}" for p in ("packet_length", "fwd_packet_length", "rev_packet_length") for s in _STAT_SUFFIXES]
IAT_FEATURES = [f"{p}_{s}" for p in ("iat", "fwd_iat", "rev_iat") for s in _STAT_SUFFIXES]
BURST_FEATURES = ["number_of_bursts", "mean_burst_size", "maximum_burst_size", "idle_gap_count", "maximum_idle_gap"]
FLOW_FEATURES = FLOW_COUNT_FEATURES + PACKET_LENGTH_FEATURES + IAT_FEATURES + BURST_FEATURES

TLS_STRUCTURAL_NUMERIC = ["clienthello_present", "serverhello_present", "sni_present"]
TLS_STRUCTURAL_CATEGORICAL = ["tls_version", "alpn_value"]
TLS_STRUCTURAL_FEATURES = TLS_STRUCTURAL_NUMERIC + TLS_STRUCTURAL_CATEGORICAL

SEQUENCE_FEATURES = ["sequence_packet_lengths", "sequence_relative_times", "sequence_directions", "sequence_tcp_flags"]

# Columns that must never enter a model matrix, with the reason.
FORBIDDEN: Dict[str, str] = {
    "corpus_index": "row identifier",
    "model_safe_index": "row identifier",
    "flow_id": "flow identifier derived from capture hash and 5-tuple",
    "flow_instance": "per-5-tuple counter",
    "dataset_id": "dataset identity equals label at source level",
    "source_file": "capture file name",
    "capture_id": "capture identity",
    "capture_flow_index": "position inside a capture",
    "family_group": "malware family is a post-labelling annotation",
    "malware_family": "malware family is a post-labelling annotation",
    "collection_date": "absolute date",
    "environment": "collection environment annotation",
    "os": "collection environment annotation",
    "forward_endpoint": "IP address and port",
    "reverse_endpoint": "IP address and port",
    "src_ip": "IP address", "dst_ip": "IP address", "src_port": "port", "dst_port": "port",
    "source_ip": "IP address", "destination_ip": "IP address",
    "source_port": "port", "destination_port": "port", "mac_address": "MAC address",
    "start_time": "absolute timestamp", "end_time": "absolute timestamp", "timestamp": "absolute timestamp",
    "behavioral_hash": "duplicate-group key (used for grouping only)",
    "label": "target", "binary_label": "target", "y": "target",
    "clienthello_parse_error": "parser diagnostic",
    "clienthello_record_truncated": "fingerprint-integrity diagnostic",
    "sequence_original_length": "storage diagnostic",
    "sequence_truncated": "storage diagnostic",
    "sni": "raw server name", "sni_value": "raw server name", "server_name": "raw server name",
    "ja4_implementation": "provenance metadata, not model feature",
    "ja4_version": "provenance metadata, not model feature",
}
FORBIDDEN_SUBSTRINGS = ("_ip", "ip_", "port", "mac_", "timestamp", "endpoint", "dataset", "capture", "family", "source_file")


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    dtype: str                    # numeric | boolean | categorical | sequence
    family: str                   # FLOW | TLS_STRUCTURAL | JA3 | JA4 | UNUSED_FINGERPRINT | SEQUENCE
    extraction: str
    availability: str
    leakage_risk: str             # LOW | MEDIUM | HIGH
    justification: str
    preprocessing: str
    tracks: Sequence[str] = field(default_factory=tuple)

    def to_dict(self):
        d = asdict(self)
        d["tracks"] = list(self.tracks)
        return d


CANONICAL_TRACKS = ("A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW")


@dataclass(frozen=True)
class TrackSpec:
    track: str
    description: str
    families: Sequence[str]
    population: str               # ALL | JA3_AVAILABLE | JA4_AVAILABLE
    canonical: bool = True

    def to_dict(self):
        return {"track": self.track, "description": self.description, "families": list(self.families),
                "population": self.population, "canonical": self.canonical}


TRACKS: Dict[str, TrackSpec] = {
    "A_FLOW": TrackSpec("A_FLOW", "Flow behaviour + TLS structural metadata (no fingerprints)", ("FLOW", "TLS_STRUCTURAL"), "ALL"),
    "B_JA3": TrackSpec("B_JA3", "JA3 fingerprint only", ("JA3",), "JA3_AVAILABLE"),
    "C_JA4": TrackSpec("C_JA4", "JA4 fingerprint only", ("JA4",), "JA4_AVAILABLE"),
    "D_JA3_FLOW": TrackSpec("D_JA3_FLOW", "JA3 + flow behaviour + TLS structural", ("JA3", "FLOW", "TLS_STRUCTURAL"), "JA3_AVAILABLE"),
    "E_JA4_FLOW": TrackSpec("E_JA4_FLOW", "JA4 + flow behaviour + TLS structural", ("JA4", "FLOW", "TLS_STRUCTURAL"), "JA4_AVAILABLE"),
    # ---- non-canonical feature sets (ablation / paired comparison / diagnostics) ----------
    "A_FLOW@JA3POP": TrackSpec("A_FLOW@JA3POP", "Track A features on the JA3-available population (paired contrast with D)",
                               ("FLOW", "TLS_STRUCTURAL"), "JA3_AVAILABLE", canonical=False),
    "A_FLOW@JA4POP": TrackSpec("A_FLOW@JA4POP", "Track A features on the JA4-available population (paired contrast with E)",
                               ("FLOW", "TLS_STRUCTURAL"), "JA4_AVAILABLE", canonical=False),
    "A0_FLOW_STRICT": TrackSpec("A0_FLOW_STRICT", "Flow behaviour only, without TLS structural metadata (ablation)",
                                ("FLOW",), "ALL", canonical=False),
    "P_AVAILABILITY_PROBE": TrackSpec("P_AVAILABILITY_PROBE", "Shortcut probe: handshake presence / availability flags only",
                                      ("AVAILABILITY",), "ALL", canonical=False),
}


def _spec(name, dtype, family, extraction, availability, risk, why, prep, tracks):
    return FeatureSpec(name, dtype, family, extraction, availability, risk, why, prep, tuple(tracks))


def _tracks_for(family: str) -> List[str]:
    return [t for t, s in TRACKS.items() if family in s.families]


def build_registry() -> Dict[str, FeatureSpec]:
    reg: Dict[str, FeatureSpec] = {}
    for f in FLOW_COUNT_FEATURES:
        reg[f] = _spec(f, "numeric", "FLOW", "pipeline.feature_extraction.extract_flow_level_features", "all flows",
                       "MEDIUM", "Volume/rate statistics; sensitive to capture duration and network path (environment).",
                       "median imputation fitted on training fold (+missing indicator); standardised for linear models", _tracks_for("FLOW"))
    for f in PACKET_LENGTH_FEATURES:
        reg[f] = _spec(f, "numeric", "FLOW", "pipeline.feature_extraction.extract_packet_length_features (IP length)",
                       "NaN when the direction has no packets", "LOW",
                       "Packet-size distribution of encrypted records; MTU/encapsulation can differ by environment.",
                       "median imputation fitted on training fold + missing indicator", _tracks_for("FLOW"))
    for f in IAT_FEATURES:
        reg[f] = _spec(f, "numeric", "FLOW", "pipeline.feature_extraction.extract_iat_features",
                       "NaN when fewer than two packets in the direction", "MEDIUM",
                       "Timing depends on RTT and host load, which are environment properties.",
                       "median imputation fitted on training fold + missing indicator", _tracks_for("FLOW"))
    for f in BURST_FEATURES:
        reg[f] = _spec(f, "numeric", "FLOW", "pipeline.feature_extraction.extract_burst_features (1.0 s idle threshold)",
                       "NaN for single-packet flows", "MEDIUM", "Burst structure; threshold not tuned.",
                       "median imputation fitted on training fold + missing indicator", _tracks_for("FLOW"))
    for f in TLS_STRUCTURAL_NUMERIC:
        reg[f] = _spec(f, "boolean", "TLS_STRUCTURAL", "first ClientHello/ServerHello in first TCP segment",
                       "all flows (False when absent)", "HIGH",
                       "Handshake presence is an availability indicator whose base rate differs strongly between capture "
                       "sources; it can identify the source rather than behaviour (see P_AVAILABILITY_PROBE).",
                       "cast to 0/1", _tracks_for("TLS_STRUCTURAL") + ["P_AVAILABILITY_PROBE"])
    reg["tls_version"] = _spec("tls_version", "categorical", "TLS_STRUCTURAL", "1.3 if ClientHello has supported_versions else 1.2",
                               "flows with a parsed ClientHello", "HIGH",
                               "TLS version tracks the client stack and collection year (2017 vs 2024-2026 here).",
                               "one-hot with explicit __MISSING__ level", _tracks_for("TLS_STRUCTURAL"))
    reg["alpn_value"] = _spec("alpn_value", "categorical", "TLS_STRUCTURAL", "first ALPN protocol in ClientHello",
                              "flows with a parsed ClientHello", "MEDIUM", "Application protocol offered by the client.",
                              "one-hot (min frequency on training fold) with __UNKNOWN__ and __MISSING__ levels", _tracks_for("TLS_STRUCTURAL"))
    reg["ja3_hash"] = _spec("ja3_hash", "categorical", "JA3", "MD5 of JA3 string (GREASE removed)", "flows with a parsed ClientHello",
                            "HIGH", "Client TLS stack identifier; also identifies OS/browser version and therefore collection era.",
                            "one-hot / frequency / hashing encoders fitted on training fold; unseen values -> __UNKNOWN__", _tracks_for("JA3"))
    reg["ja4"] = _spec("ja4", "categorical", "JA4", "JA4 (ETTH implementation, see pipeline.tls_fingerprinting.generate_ja4)",
                       "flows with a parsed ClientHello", "HIGH", "Client TLS stack identifier (sorted, more stable than JA3).",
                       "one-hot / frequency / hashing encoders fitted on training fold; unseen values -> __UNKNOWN__", _tracks_for("JA4"))
    for f, why in (("ja3_string", "raw JA3 string (same information as ja3_hash)"),
                   ("ja3s_hash", "server fingerprint; not part of the research question and can reflect interception proxies"),
                   ("ja3s_string", "raw JA3S string"),
                   ("ja4_v2", "FoxIO-compliant JA4 v2 fingerprint; see pipeline.tls_fingerprinting.generate_ja4_foxio")):
        reg[f] = _spec(f, "categorical", "UNUSED_FINGERPRINT", "pipeline.tls_fingerprinting", "flows with handshake",
                       "HIGH", why, "not used by any track", ())
    for f in SEQUENCE_FEATURES:
        reg[f] = _spec(f, "sequence", "SEQUENCE", "per-packet lists from flow reconstruction (first 1000 packets)",
                       "all flows", "MEDIUM", "Observable packet sizes, timing, direction and TCP flags (no payload).",
                       "Phase 10 sequence builder only (training-fold normalisation)", ())
    return reg


REGISTRY: Dict[str, FeatureSpec] = build_registry()
AVAILABILITY_FEATURES = TLS_STRUCTURAL_NUMERIC


class LeakageError(ValueError):
    pass


def assert_model_safe(columns: Iterable[str]) -> None:
    """Raise LeakageError if any column is forbidden, unregistered, or not model-eligible."""
    problems = []
    for c in columns:
        if c in FORBIDDEN:
            problems.append(f"{c}: forbidden ({FORBIDDEN[c]})")
            continue
        spec = REGISTRY.get(c)
        if spec is None:
            low = c.lower()
            hit = [s for s in FORBIDDEN_SUBSTRINGS if s in low]
            problems.append(f"{c}: not in feature registry" + (f" (matches forbidden pattern {hit})" if hit else ""))
            continue
        if spec.family in ("UNUSED_FINGERPRINT", "SEQUENCE"):
            problems.append(f"{c}: family {spec.family} is not eligible for tabular model matrices")
    if problems:
        raise LeakageError("Model matrix rejected: " + "; ".join(problems))


def track_columns(track: str) -> Dict[str, List[str]]:
    """Return {'numeric': [...], 'categorical': [...]} for a track, in a fixed order."""
    if track not in TRACKS:
        raise KeyError(f"Unknown track {track}")
    fams = TRACKS[track].families
    numeric: List[str] = []
    categorical: List[str] = []
    if "FLOW" in fams:
        numeric += FLOW_FEATURES
    if "TLS_STRUCTURAL" in fams:
        numeric += TLS_STRUCTURAL_NUMERIC
        categorical += TLS_STRUCTURAL_CATEGORICAL
    if "AVAILABILITY" in fams:
        numeric += AVAILABILITY_FEATURES
    if "JA3" in fams:
        categorical.append("ja3_hash")
    if "JA4" in fams:
        categorical.append("ja4")
    cols = numeric + categorical
    assert_model_safe(cols)
    return {"numeric": numeric, "categorical": categorical}


def population_mask(df, track: str):
    pop = TRACKS[track].population
    if pop == "ALL":
        return df.index == df.index
    if pop == "JA3_AVAILABLE":
        return df["ja3_hash"].notna().to_numpy()
    if pop == "JA4_AVAILABLE":
        return df["ja4"].notna().to_numpy()
    raise ValueError(pop)


def registry_table() -> List[Dict]:
    return [REGISTRY[k].to_dict() for k in sorted(REGISTRY)]


def schema_fingerprint(track: str) -> str:
    """Stable identifier of a track's input schema (used for inference compatibility checks)."""
    import hashlib
    cols = track_columns(track)
    payload = f"{SCHEMA_VERSION}|{track}|num:{','.join(cols['numeric'])}|cat:{','.join(cols['categorical'])}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]
