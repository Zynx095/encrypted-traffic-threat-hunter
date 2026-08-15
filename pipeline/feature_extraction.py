"""
Phase 6 Step 6: Behavioral Feature Extraction
"""
import numpy as np
from typing import Dict, Any, List, Optional

BURST_IDLE_THRESHOLD = 1.0 # PENDING_PILOT_VALIDATION

def safe_div(a, b, default=0.0):
    if b == 0: return default
    return a / b

def compute_stats(arr: Any, prefix: str) -> Dict[str, float]:
    """Computes standard statistics for a numeric sequence."""
    if len(arr) == 0:
        return {
            f"{prefix}_mean": np.nan,
            f"{prefix}_median": np.nan,
            f"{prefix}_std": np.nan,
            f"{prefix}_min": np.nan,
            f"{prefix}_max": np.nan,
            f"{prefix}_p25": np.nan,
            f"{prefix}_p75": np.nan,
            f"{prefix}_p90": np.nan,
            f"{prefix}_p95": np.nan,
        }
    
    a = np.array(arr)
    return {
        f"{prefix}_mean": float(np.mean(a)),
        f"{prefix}_median": float(np.median(a)),
        f"{prefix}_std": float(np.std(a)) if len(a) > 1 else 0.0,
        f"{prefix}_min": float(np.min(a)),
        f"{prefix}_max": float(np.max(a)),
        f"{prefix}_p25": float(np.percentile(a, 25)),
        f"{prefix}_p75": float(np.percentile(a, 75)),
        f"{prefix}_p90": float(np.percentile(a, 90)),
        f"{prefix}_p95": float(np.percentile(a, 95)),
    }

def extract_flow_level_features(row: Dict[str, Any]) -> Dict[str, Any]:
    duration = float(row.get("duration", 0.0))
    total_pkts = int(row.get("packet_count", 0))
    fwd_pkts = int(row.get("forward_packet_count", 0))
    rev_pkts = int(row.get("reverse_packet_count", 0))
    total_bytes = int(row.get("byte_count", 0))
    fwd_bytes = int(row.get("forward_byte_count", 0))
    rev_bytes = int(row.get("reverse_byte_count", 0))
    
    return {
        "flow_duration": duration,
        "total_packets": total_pkts,
        "total_bytes": total_bytes,
        "forward_packets": fwd_pkts,
        "reverse_packets": rev_pkts,
        "forward_bytes": fwd_bytes,
        "reverse_bytes": rev_bytes,
        "packets_per_second": safe_div(total_pkts, duration, np.nan),
        "bytes_per_second": safe_div(total_bytes, duration, np.nan),
        "forward_packet_ratio": safe_div(fwd_pkts, total_pkts, 0.0),
        "reverse_packet_ratio": safe_div(rev_pkts, total_pkts, 0.0),
        "forward_byte_ratio": safe_div(fwd_bytes, total_bytes, 0.0),
        "reverse_byte_ratio": safe_div(rev_bytes, total_bytes, 0.0),
        "packet_count_asymmetry": safe_div(fwd_pkts - rev_pkts, total_pkts, 0.0),
        "byte_count_asymmetry": safe_div(fwd_bytes - rev_bytes, total_bytes, 0.0)
    }

def extract_packet_length_features(row: Dict[str, Any]) -> Dict[str, Any]:
    lengths = row.get("packet_lengths", [])
    dirs = row.get("direction_sequence", [])
    
    if len(lengths) == 0:
        fwd_len = []
        rev_len = []
    else:
        fwd_len = [lengths[i] for i in range(len(lengths)) if dirs[i] == 1]
        rev_len = [lengths[i] for i in range(len(lengths)) if dirs[i] == -1]
    
    feats = {}
    feats.update(compute_stats(lengths, "packet_length"))
    feats.update(compute_stats(fwd_len, "fwd_packet_length"))
    feats.update(compute_stats(rev_len, "rev_packet_length"))
    return feats

def extract_iat_features(row: Dict[str, Any]) -> Dict[str, Any]:
    times = row.get("relative_times", [])
    dirs = row.get("direction_sequence", [])
    
    if len(times) > 1:
        iats = np.diff(times).tolist()
    else:
        iats = []
        
    if len(times) == 0:
        fwd_times = []
        rev_times = []
    else:
        fwd_times = [times[i] for i in range(len(times)) if dirs[i] == 1]
        rev_times = [times[i] for i in range(len(times)) if dirs[i] == -1]
        
    if len(fwd_times) > 1:
        fwd_iats = np.diff(fwd_times).tolist()
    else:
        fwd_iats = []
        
    if len(rev_times) > 1:
        rev_iats = np.diff(rev_times).tolist()
    else:
        rev_iats = []
        
    feats = {}
    feats.update(compute_stats(iats, "iat"))
    feats.update(compute_stats(fwd_iats, "fwd_iat"))
    feats.update(compute_stats(rev_iats, "rev_iat"))
    return feats

def extract_burst_features(row: Dict[str, Any]) -> Dict[str, Any]:
    times = row.get("relative_times", [])
    if len(times) < 2:
        return {
            "number_of_bursts": 0,
            "mean_burst_size": np.nan,
            "maximum_burst_size": np.nan,
            "idle_gap_count": 0,
            "maximum_idle_gap": np.nan
        }
        
    iats = np.diff(times)
    burst_sizes = []
    current_burst = 1
    
    idle_gaps = []
    
    for iat in iats:
        if iat > BURST_IDLE_THRESHOLD:
            burst_sizes.append(current_burst)
            idle_gaps.append(iat)
            current_burst = 1
        else:
            current_burst += 1
            
    burst_sizes.append(current_burst)
    
    return {
        "number_of_bursts": len(burst_sizes),
        "mean_burst_size": float(np.mean(burst_sizes)),
        "maximum_burst_size": float(np.max(burst_sizes)),
        "idle_gap_count": len(idle_gaps),
        "maximum_idle_gap": float(np.max(idle_gaps)) if len(idle_gaps) > 0 else np.nan
    }

def extract_tls_features(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tls_version": row.get("tls_version", np.nan),
        "clienthello_present": row.get("clienthello_present", False),
        "serverhello_present": row.get("serverhello_present", False),
        "sni_present": row.get("sni_present", False),
        "alpn_value": row.get("alpn", None),
        "ja3_hash": row.get("ja3_hash", None),
        "ja3_string": row.get("ja3_string", None),
        "ja3s_hash": row.get("ja3s_hash", None),
        "ja3s_string": row.get("ja3s_string", None),
        "ja4": row.get("ja4", None)
    }

def build_feature_record(row: Dict[str, Any]) -> Dict[str, Any]:
    record = {}
    
    # 1. Provenance / Audit (Not for model)
    record["flow_id"] = row.get("flow_id")
    record["dataset_id"] = row.get("dataset_id")
    record["source_file"] = row.get("source_file")
    
    # 2. Label
    ds_id = row.get("dataset_id")
    if ds_id == "DS-008":
        record["label"] = "MALICIOUS"
    elif ds_id == "DS-004":
        record["label"] = "BENIGN_VALIDATION"
    else:
        record["label"] = "UNKNOWN"
        
    # 3. Features
    record.update(extract_flow_level_features(row))
    record.update(extract_packet_length_features(row))
    record.update(extract_iat_features(row))
    record.update(extract_burst_features(row))
    record.update(extract_tls_features(row))
    
    # Keep original sequences explicitly (for interim/processed tier, can be dropped later)
    # Ensure they are native lists, not numpy arrays, for pure Python representation consistency
    pl = row.get("packet_lengths", [])
    record["sequence_packet_lengths"] = pl.tolist() if hasattr(pl, 'tolist') else pl
    
    rt = row.get("relative_times", [])
    record["sequence_relative_times"] = rt.tolist() if hasattr(rt, 'tolist') else rt
    
    ds = row.get("direction_sequence", [])
    record["sequence_directions"] = ds.tolist() if hasattr(ds, 'tolist') else ds
    
    tf = row.get("tcp_flags", [])
    record["sequence_tcp_flags"] = tf.tolist() if hasattr(tf, 'tolist') else tf
    
    # Ensure NO IPs, Ports, MACs, or Absolute Timestamps are copied over.
    return record
