# Phase 11 — Sensor Validation and Deployment Notes

## 1. What has been validated

| Component | Validated how | Not validated |
|---|---|---|
| Zeek adapter | synthetic `conn`/`ssl` fixtures and unit tests: correlation in both orders, duplicates, expiry, overflow, malformed and unknown records, semantics | real Zeek output; Zeek ja3/ja4 package versions |
| Suricata adapter | synthetic EVE fixture and unit tests: flow/tls/alert correlation, duration from timestamps, duplicates, late events, alerts not used as labels | real Suricata output; byte-counter semantics |
| eBPF adapter | synthetic JSON fixture and unit tests | any native eBPF program (none exists in ETTH) |
| Sensor → pipeline | `tests/test_cross_phase_integration.py`: all five tracks, strict-JSON events, WebSocket broadcast | a running sensor feeding the live stream (not wired) |
| Live capture | `tests/test_live_offline_parity.py`: synthetic packets give the same flows and features as the offline PCAP pipeline | native capture: the integration host has no Npcap ("wpcap.dll missing"), so live capture reports `CAPTURE_UNAVAILABLE` |

Synthetic fixtures test software contracts. They are not evidence of detection quality.

## 2. Platform matrix

| Component | Windows | Linux | macOS | Privileges |
|---|:---:|:---:|:---:|---|
| Zeek / Suricata log adapters | ✅ | ✅ | ✅ | user |
| eBPF JSON adapter | ✅ | ✅ | ✅ | user |
| Native eBPF probes | ❌ | not included in ETTH | ❌ | root / `CAP_BPF` |
| Live capture (Scapy) | needs Npcap | needs libpcap | needs BPF device | admin / root |

## 3. Runtime status endpoint

`GET /api/sensors/status` reports what each source can do and whether it is actually feeding the live stream:

```json
{
  "note": "adapter_available means the parser/adapter can be imported; it does not mean a sensor is running. ...",
  "live_capture": {"available": false, "error": "Packet capture driver unavailable (...wpcap.dll missing). Install Npcap ...",
                   "state": "STOPPED", "ingestion_active": false, "connected_to_live_stream": true, "interfaces": ["..."]},
  "ebpf": {"adapter_available": true, "native_probe_included": false, "available": false, "os": "Windows",
           "ingestion_active": false, "connected_to_live_stream": false, "...": "..."},
  "zeek": {"adapter_available": true, "ingestion_active": false, "connected_to_live_stream": false,
           "process_managed_by_etth": false, "parser": "ZeekCorrelator", "supported_logs": ["conn.log", "ssl.log"]},
  "suricata": {"adapter_available": true, "ingestion_active": false, "connected_to_live_stream": false,
               "process_managed_by_etth": false, "parser": "SuricataCorrelator", "supported_events": ["flow", "tls", "alert"]}
}
```

## 4. Test commands

```bash
python -m pytest -q -p no:cacheprovider tests/test_sensors_zeek.py tests/test_sensors_suricata.py \
    tests/test_sensors_ebpf.py tests/test_sensors_pipeline_integration.py tests/test_cross_phase_integration.py \
    tests/test_inference_contract.py tests/test_live_offline_parity.py tests/test_sensor_status_api.py
```

## 5. Before claiming sensor support in production

1. Run Zeek and Suricata on a shared, authorised PCAP. Compare their JA3 values with ETTH's on the same ClientHellos, and record any differences.
2. Decide how sensor flows reach the stream (log tailing or a push API) and add that path with authentication and back-pressure.
3. Either retrain models on sensor-observable features with sensor provenance, or keep sensor flows limited to the JA3-only track and display-only enrichment.
4. Implement and validate a real eBPF collector if host telemetry is required.
