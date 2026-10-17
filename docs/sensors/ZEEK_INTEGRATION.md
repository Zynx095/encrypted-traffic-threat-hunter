# Phase 11 — Zeek Integration Guide

> **Status.** This is an adapter for Zeek JSON logs (`backend/event_sources/zeek_source.py`). It has been tested only with synthetic fixtures (`data/fixtures/sensors/zeek_*_synthetic.json`). No Zeek installation was used in validation, and the adapter is not connected to the live stream. Field semantics follow [`CROSS_PHASE_CONTRACTS.md`](../integration/CROSS_PHASE_CONTRACTS.md).

## 1. Logs used

| Log | Use |
|---|---|
| `conn.log` | 5-tuple, duration, packet and byte counters, connection state |
| `ssl.log` | negotiated version and cipher, SNI, selected ALPN, JA3/JA3S (`zeek/salesforce/ja3`), JA4 (`foxio/ja4`) |

`x509.log` and other logs are **not** used. If they are fed in, they are counted as `unsupported_records`.

## 2. Field mapping

| Zeek field | Canonical field | Notes |
|---|---|---|
| `uid` | `flow_id`, `sensor_record_id` | correlation key |
| `id.orig_h`:`id.orig_p` / `id.resp_h`:`id.resp_p` | `forward_endpoint` / `reverse_endpoint` | Flat keys and a nested `id` object are both accepted. Endpoints are `None` when unknown (no `0.0.0.0`/port 0) |
| `proto` | `protocol` | Only TCP/UDP. Other protocols are skipped and counted |
| `ts` | `start_time` | epoch seconds |
| `duration` | `flow_duration` | `None` if absent. Rates are `None` when duration is 0 |
| `orig_pkts` / `resp_pkts` | `forward_packets` / `reverse_packets` | |
| `orig_ip_bytes` / `resp_ip_bytes` | `forward_bytes` / `reverse_bytes` | `byte_count_semantics=IP_LENGTH` (same meaning as ETTH) |
| `orig_bytes` / `resp_bytes` | same fields, used only if `*_ip_bytes` are absent | `byte_count_semantics=TRANSPORT_PAYLOAD` (not ETTH's meaning) |
| `server_name` | `sni`, `sni_present` | lowercased |
| `version` | `tls_version_observed` (`NEGOTIATED`) | **not** `tls_version`: ETTH's feature is the version the client *offers* |
| `next_protocol` | `alpn_negotiated` | **not** `alpn_value`: ETTH's feature is the first ALPN the client *offers* |
| `cipher` | `tls_cipher` | |
| `ja3` | `ja3_hash` | must be MD5 hex. Other values are rejected (`ja3_rejected_reason`) |
| `ja3s` | `ja3s_hash` | |
| `ja4` | `ja4`, `ja4_implementation=FOXIO_JA4` | refused by models trained on ETTH JA4 |

`serverhello_present` is `True` only when `version`, `cipher` or `ja3s` is present. `established` describes handshake completion; it is exported as `tls_established` and never used to infer a ServerHello.

## 3. Correlation (`ZeekCorrelator`)

Zeek writes `ssl.log` when the handshake completes and `conn.log` when the connection ends. Records may still arrive in either order, for example when files are ingested one after the other.

- `conn` and `ssl` records with the same `uid` are merged into one flow, whichever arrives first.
- A `conn` record still unmatched after the TTL (60 s, wall clock), at cache overflow, or at `stop()` is **emitted without TLS enrichment**. It is never dropped.
- An unmatched `ssl` record is counted as `orphan_ssl_dropped`. Without the `conn` record it cannot become a flow.
- Duplicate `conn`/`ssl` records and `ssl` records arriving after their flow was emitted are counted, not re-emitted.

For file ingestion, ingest `ssl.log` first, then `conn.log`, so that TLS enrichment does not depend on the TTL.

## 4. Usage

```python
from pathlib import Path
from backend.event_sources.zeek_source import ZeekEventSource
from backend.detection_pipeline import detection_pipeline

source = ZeekEventSource()
await source.start()
await source.ingest_file(Path("ssl.log"), log_hint="ssl")
await source.ingest_file(Path("conn.log"), log_hint="conn")
await source.stop()                      # flushes unmatched conn records
while not source.queue.empty():
    event = detection_pipeline.process_flow(source.queue.get_nowait(), track="B_JA3", mode="LIVE")
```

Zeek configuration (not validated here):
- load `policy/tuning/json-logs.zeek`;
- install the `zeek/salesforce/ja3` and `foxio/ja4` packages if fingerprints are wanted.
