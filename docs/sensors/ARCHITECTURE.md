# Phase 11 — Sensor Ingestion Architecture

> **Integration status (Phase 8–12 integration).** The Zeek, Suricata and eBPF components are **adapters**: they parse log lines or JSON events and normalise them into the canonical ETTH flow contract. They are not running sensors, and none of them is connected to the live WebSocket stream. All of them are validated only against synthetic fixtures. The authoritative field contract is in [`docs/integration/CROSS_PHASE_CONTRACTS.md`](../integration/CROSS_PHASE_CONTRACTS.md).

## 1. Purpose

The adapters let ETTH consume flow and TLS-handshake metadata produced by external tools:
- **Zeek:** `conn.log` + `ssl.log`, JSON;
- **Suricata:** EVE `flow`, `tls` and `alert` events;
- **eBPF:** JSON flow summaries from an external collector. ETTH ships no eBPF program.

Boundaries:
1. **No decryption.** The adapters read only metadata fields that the sensors themselves log.
2. **No fabrication.** Missing JA3/JA4/SNI, endpoints, durations and counters stay absent or `None`. Unsupported protocols are skipped and counted, never relabelled as TCP.
3. **Provenance.** Every sensor flow carries `sensor_type`, `sensor_record_id`, `feature_provenance=SENSOR_AGGREGATE`, `byte_count_semantics` and, where present, `ja4_implementation`.

## 2. Data path

```
Zeek conn/ssl ──► ZeekCorrelator (uid) ───────┐
Suricata EVE ───► SuricataCorrelator (flow_id)├──► canonical flow dict ──► DetectionPipeline.process_flow()
eBPF JSON ──────► EBPFEventSource ────────────┘         (called by tests / tooling; not by the running server)
```

`DetectionPipeline` accepts sensor flows. The inference engine then applies the provenance rules:

| Track | What happens to a sensor flow | Reason |
|---|---|---|
| A, D, E (flow features) | SKIPPED | sensors provide aggregate counters, not ETTH packet-level statistics |
| C, E (JA4) | SKIPPED | Zeek and Suricata compute FoxIO JA4; the models were trained on the non-conformant ETTH JA4 |
| B (JA3 only) | scored | JA3 is specification-compatible; sensor JA3 values are usually outside the training vocabulary and flagged `UNSEEN_CATEGORY` |

Only corpus replay and live capture are wired to `/ws/live-stream`.

## 3. Normalisation matrix

| Canonical field | Zeek | Suricata | eBPF (collector contract) |
|---|---|---|---|
| `sensor_record_id` | `uid` | `flow_id` | `flow_id` (optional) |
| endpoints | `id.orig_*` → forward, `id.resp_*` → reverse | `src_*` / `dest_*` | `saddr:sport` / `daddr:dport` |
| `flow_duration` (s) | `duration` | `flow.end − flow.start` (fallback `flow.age`, integer seconds, tagged) | `duration_ns`, `end_ns − start_ns`, or `flow_duration` |
| packets | `orig_pkts` / `resp_pkts` | `flow.pkts_toserver` / `pkts_toclient` | `packets_sent` / `packets_recv` |
| bytes and `byte_count_semantics` | `*_ip_bytes` (`IP_LENGTH`); else `orig_bytes`/`resp_bytes` (`TRANSPORT_PAYLOAD`) | `flow.bytes_to*` (`UNKNOWN`: not documented as IP length) | as declared, else `UNKNOWN` |
| negotiated TLS version | `version` → `tls_version_observed` | `tls.version` → `tls_version_observed` | `tls_version` → `tls_version_observed` (collector-defined) |
| `alpn_value` (first offered) | not available | `tls.client_alpns[0]` | not mapped |
| `alpn_negotiated` | `next_protocol` | `tls.server_alpns[0]` | `sensor_alpn` |
| `ja3_hash` | `ja3` (Zeek ja3 package) | `tls.ja3.hash`, or MD5 of `tls.ja3.string` | `ja3_hash`/`ja3` (MD5 hex or complete JA3 string) |
| `ja4` and `ja4_implementation` | `ja4` → `FOXIO_JA4` | `tls.ja4` → `FOXIO_JA4` | `ja4` → declared, or `UNKNOWN` |
| alerts | — | `alert.*` → `sensor_alerts` (context only) | — |

The ETTH model feature `tls_version` is never set from a sensor. ETTH defines it as the version **offered** in the ClientHello.

## 4. Reliability

| Behaviour | Zeek | Suricata | eBPF |
|---|---|---|---|
| Correlation | UID, in either order | `flow_id`; the `flow` event finalises a flow | no correlation (one event per flow) |
| Bounded memory | yes, with a TTL (default 60 s, wall clock) | yes, with a TTL | not applicable |
| Expiry and overflow | expired or overflowing `conn` records are **emitted without TLS**; orphan `ssl` records are counted | tls/alert entries without a flow event are counted | not applicable |
| Duplicates and late records | suppressed and counted | suppressed and counted | duplicate collector `flow_id`s suppressed |

All adapters count malformed lines and unsupported record types. Their queues are bounded, and queue overflow is counted (`queue_dropped`).
