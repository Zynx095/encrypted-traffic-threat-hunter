# Phase 11 — Sensor Deployment & Validation Guide

## 1. Overview & Verification Strategy
This document outlines reproducible setup procedures, environment capability diagnostics, and verification protocols for the ETTH Sensor Layer.

---

## 2. Platform Compatibility Matrix

| Component | Windows 10/11 | Linux (Ubuntu/Debian) | macOS | Minimum Privileges |
| :--- | :---: | :---: | :---: | :--- |
| **Zeek JSON Ingest** | ✅ Full Support | ✅ Full Support | ✅ Full Support | Standard User |
| **Suricata EVE Ingest** | ✅ Full Support | ✅ Full Support | ✅ Full Support | Standard User |
| **eBPF Ingestion Adapter** | ✅ Full Support | ✅ Full Support | ✅ Full Support | Standard User |
| **Native eBPF Kernel Probes** | ❌ Unsupported | ✅ Linux 5.8+ | ❌ Unsupported | `CAP_BPF` / Root |
| **Live Scapy Sniffing** | ⚠️ Requires Npcap | ✅ Native libpcap | ✅ BPF device | Admin / Root |

---

## 3. Real Environment Capability Validation

ETTH includes automatic runtime capability discovery:

```bash
curl http://localhost:8000/api/sensors/status
```

### Sample Diagnostics Output:
```json
{
  "live_capture": {
    "available": true,
    "library": "Scapy 2.7.0",
    "interfaces": [
      {"id": "\\Device\\NPF_{...}", "name": "Ethernet0", "ip": "192.168.1.100"}
    ]
  },
  "ebpf": {
    "available": false,
    "os": "Windows",
    "reason": "Native eBPF kernel probes require Linux (current OS: Windows). Deploy on Linux kernel >= 5.8 or use a containerized collector sending JSON telemetry."
  },
  "zeek": {
    "available": true,
    "parser": "ZeekCorrelator",
    "supported_logs": ["conn.log", "ssl.log", "x509.log"]
  },
  "suricata": {
    "available": true,
    "parser": "SuricataCorrelator",
    "supported_events": ["flow", "tls", "alert"]
  }
}
```

---

## 4. Testing & Verification Runbook

### Automated Pytest Suite
```bash
python -m pytest tests/test_sensors_zeek.py \
                 tests/test_sensors_suricata.py \
                 tests/test_sensors_ebpf.py \
                 tests/test_sensors_pipeline_integration.py -v
```

### Verification Checklist:
- [x] Correlates Zeek `conn.log` and `ssl.log` across asynchronous timestamps.
- [x] Preserves missing JA3/JA4 fingerprints without synthetic imputation.
- [x] Correlates Suricata `flow`, `tls`, and `alert` records by `flow_id`.
- [x] Enriches threat alerts without violating the zero-decryption boundary.
- [x] Validates eBPF ring-buffer contracts and normalizes nanosecond timing.
- [x] Detects platform capabilities without crashing on Windows.
- [x] Passes normalized sensor flows through `DetectionPipeline` and `TargetResolver`.
