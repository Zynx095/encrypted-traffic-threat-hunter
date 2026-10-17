# Phase 11 — Suricata Integration Guide

> **Status.** This is an adapter for Suricata EVE JSON (`backend/event_sources/suricata_source.py`). It has been tested only with a synthetic fixture (`data/fixtures/sensors/suricata_eve_synthetic.json`). No Suricata installation was used, and the adapter is not connected to the live stream. Field semantics follow [`CROSS_PHASE_CONTRACTS.md`](../integration/CROSS_PHASE_CONTRACTS.md).

## 1. Events used

| `event_type` | Use |
|---|---|
| `flow` | finalises a flow: endpoints, timestamps, packet and byte counters, state |
| `tls` | SNI, negotiated version, JA3/JA3S, JA4 (Suricata ≥ 7), client and server ALPN lists |
| `alert` | signature metadata, kept as third-party context |

Other event types (`stats`, `dns`, …) are counted as `ignored_event_types`.

## 2. Field mapping

| EVE field | Canonical field | Notes |
|---|---|---|
| `flow_id` | `flow_id`, `sensor_record_id` | correlation key |
| `src_ip`:`src_port` / `dest_ip`:`dest_port` | `forward_endpoint` / `reverse_endpoint` | Records without endpoints are counted as invalid |
| `proto` | `protocol` | Only TCP/UDP. Others are skipped and counted |
| `flow.start`, `flow.end` | `start_time`, `end_time`, `flow_duration = end − start` | microsecond timestamps |
| `flow.age` | `flow_duration`, only when start or end is missing | `age` has integer-second resolution; the fallback is recorded in `sensor_duration_source` |
| `flow.pkts_toserver` / `pkts_toclient` | `forward_packets` / `reverse_packets` | |
| `flow.bytes_toserver` / `bytes_toclient` | `forward_bytes` / `reverse_bytes` | `byte_count_semantics=UNKNOWN`. The EVE documentation does not define them as IP length |
| `tls.sni` | `sni`, `sni_present` | lowercased |
| `tls.version` (e.g. `"TLS 1.3"`) | `tls_version_observed` (`NEGOTIATED`) | **not** `tls_version` |
| `tls.client_alpns[0]` | `alpn_value` | first offered ALPN, the same meaning as ETTH |
| `tls.server_alpns[0]` | `alpn_negotiated` | |
| `tls.ja3.hash` / `tls.ja3.string` | `ja3_hash` | The hash is used if present, otherwise the MD5 of the string (`ja3_derivation`) |
| `tls.ja3s.hash` | `ja3s_hash` | |
| `tls.ja4` | `ja4`, `ja4_implementation=FOXIO_JA4` | refused by models trained on ETTH JA4 |
| `alert.signature`, `signature_id`, `severity`, `category` | `sensor_alerts`, `sensor_alert_details` | context only (§4) |

`serverhello_present` is `True` only when the negotiated version, JA3S or server ALPNs are present. The mere existence of a `tls` event does not imply a ServerHello.

## 3. Correlation (`SuricataCorrelator`)

- `tls` and `alert` events are cached by `flow_id` until the `flow` event arrives. The `flow` event emits the merged flow and evicts the entry.
- The first `tls` event per flow is kept, matching ETTH's first-ClientHello policy.
- A duplicate `flow` event, or a `tls`/`alert` event that arrives after its flow was emitted, is counted (`duplicate_flow_events`, `late_events`). It is never re-emitted or re-cached.
- `tls`/`alert` entries that never meet a `flow` event expire after the TTL, or are cleared at `stop()`, and are counted (`expired_without_flow`).

## 4. Alerts are not labels

Suricata alerts are third-party signature matches. ETTH:
- surfaces them as `provenance.sensor.external_alert_signatures` in events;
- never uses them as `label`, ground truth or prediction;
- never uses them as model input. The feature allow-list contains no `sensor_*` column.

A test checks that adding or removing alerts does not change the model score.

## 5. Suricata configuration (not validated here)

```yaml
outputs:
  - eve-log:
      types:
        - alert
        - flow
        - tls:
            extended: yes
            custom: [sni, version, ja3, ja3s, ja4, client_alpns, server_alpns]
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
      ja4-fingerprints: yes
```
