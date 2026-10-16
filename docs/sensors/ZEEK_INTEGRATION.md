# Phase 11 — Zeek Integration Guide

## 1. Overview
Zeek emits structured transaction logs for network activity. For encrypted traffic threat detection, ETTH correlates two primary logs:
- `conn.log`: Network transport session records (IP 5-tuple, bytes, packets, duration, TCP state flags).
- `ssl.log`: TLS handshake metadata (TLS version, cipher suite, SNI, ALPN, JA3/JA3S, JA4).

---

## 2. Ingestion Format & Field Mappings

Zeek logs must be configured to output JSON (`@load policy/tuning/json-logs.zeek`).

### Field Mapping Reference

| Zeek Field | ETTH Flow Field | Type / Transformation |
| :--- | :--- | :--- |
| `uid` | `flow_id` | Unique connection identifier string |
| `id.orig_h` | `source_ip` / `forward_endpoint` | IPv4/IPv6 client address |
| `id.orig_p` | `source_port` | Client source port (int) |
| `id.resp_h` | `destination_ip` / `reverse_endpoint` | Server destination address |
| `id.resp_p` | `destination_port` | Server service port (443, etc.) |
| `proto` | `protocol` | Normalized to `"TCP"` or `"UDP"` |
| `duration` | `flow_duration` | Duration in seconds (float) |
| `orig_pkts` | `forward_packets` | Client-to-server packet count |
| `resp_pkts` | `reverse_packets` | Server-to-client packet count |
| `orig_bytes` | `forward_bytes` | Client-to-server payload volume |
| `resp_bytes` | `reverse_bytes` | Server-to-client payload volume |
| `server_name` | `sni` / `sni_value` | Lowercase unencrypted SNI string |
| `ja3` | `ja3_hash` | MD5 client TLS fingerprint (or None) |
| `ja3s` | `ja3s_hash` | MD5 server TLS fingerprint (or None) |
| `ja4` | `ja4` | FoxIO JA4 client signature (or None) |
| `alpn` | `alpn_value` | Negotiated protocol (e.g., `"h2"`, `"http/1.1"`) |

---

## 3. Stateful Correlation Engine (`ZeekCorrelator`)

Zeek writes `conn.log` when a connection terminates, while `ssl.log` is written when the TLS handshake concludes. Thus:
1. `ssl.log` frequently arrives before `conn.log`.
2. `conn.log` arrives without an `ssl.log` if traffic is unencrypted or mid-stream.
3. `ZeekCorrelator` holds incoming records in a bounded memory cache keyed by `uid`.
4. When both records are present, a unified flow is emitted.
5. Pending unencrypted connections are flushed on timeout or shutdown.

---

## 4. Running Zeek for ETTH

### Enabling JSON and JA3/JA4 Packages in Zeek
```bash
# Install packages using zkg
zkg install zeek/salesforce/ja3
zkg install fox-io/ja4

# In local.zeek or zeekctl.cfg:
@load policy/tuning/json-logs.zeek
@load packages
```

### Ingesting into ETTH
```python
from pathlib import Path
from backend.event_sources.zeek_source import ZeekEventSource

source = ZeekEventSource()
await source.start()
await source.ingest_file(Path("/var/log/zeek/current/ssl.log"), log_hint="ssl")
await source.ingest_file(Path("/var/log/zeek/current/conn.log"), log_hint="conn")
```
