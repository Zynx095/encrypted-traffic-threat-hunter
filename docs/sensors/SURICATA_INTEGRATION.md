# Phase 11 — Suricata Integration Guide

## 1. Overview
Suricata generates consolidated Extensible Event Format (EVE) JSON logs (`eve.json`). ETTH consumes:
- `event_type: "flow"`: Connection termination records containing timing, packet counts, and byte statistics.
- `event_type: "tls"`: Handshake events containing subject, issuer, SNI, ALPN, JA3, JA3S, and JA4.
- `event_type: "alert"`: Rule violation metadata containing signature ID, classification, and severity.

---

## 2. Ingestion Format & Field Mappings

### Field Mapping Reference

| Suricata EVE Field | ETTH Flow Field | Description |
| :--- | :--- | :--- |
| `flow_id` | `flow_id` | Suricata internal numeric 64-bit flow identifier |
| `src_ip` | `source_ip` | Source IP (client) |
| `src_port` | `source_port` | Source port |
| `dest_ip` | `destination_ip` | Destination IP (server) |
| `dest_port` | `destination_port` | Destination port |
| `proto` | `protocol` | Protocol string ("TCP", "UDP") |
| `flow.age` | `flow_duration` | Total flow active duration in seconds |
| `flow.pkts_toserver` | `forward_packets` | Packets transmitted to server |
| `flow.pkts_toclient` | `reverse_packets` | Packets received from server |
| `flow.bytes_toserver` | `forward_bytes` | Payload bytes transmitted to server |
| `flow.bytes_toclient` | `reverse_bytes` | Payload bytes received from server |
| `tls.sni` | `sni` / `sni_value` | Lowercase Server Name Indication |
| `tls.ja3.hash` | `ja3_hash` | MD5 client TLS fingerprint |
| `tls.ja3s.hash` | `ja3s_hash` | MD5 server TLS fingerprint |
| `tls.ja4` | `ja4` | Modern FoxIO JA4 fingerprint (Suricata 7+) |
| `tls.alpn` | `alpn_value` | Application layer protocol negotiation |
| `alert.signature` | `sensor_alerts` | Appended to auxiliary alert tracking list |

---

## 3. Stateful Correlation Engine (`SuricataCorrelator`)

Suricata streams events sequentially into a shared `eve.json` output file. For a single TLS connection, Suricata typically emits:
1. A `tls` event during the ClientHello/ServerHello exchange.
2. Optional `alert` events if signatures match traffic heuristics.
3. A `flow` event when the TCP connection closes or times out.

`SuricataCorrelator` caches `tls` and `alert` events in a bounded, thread-safe memory table keyed by `flow_id`. When the `flow` event arrives, the engine fuses the behavioral statistics with the TLS fingerprint and alert metadata into a complete ETTH flow object and immediately evicts the flow entry from memory.

---

## 4. Suricata Configuration for ETTH

In `suricata.yaml`:
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - flow
        - tls:
            extended: yes
            custom: [subject, issuer, sni, version, ja3, ja3s, ja4]
```

### Ingestion in Python
```python
from pathlib import Path
from backend.event_sources.suricata_source import SuricataEventSource

source = SuricataEventSource()
await source.start()
await source.ingest_file(Path("/var/log/suricata/eve.json"))
```
