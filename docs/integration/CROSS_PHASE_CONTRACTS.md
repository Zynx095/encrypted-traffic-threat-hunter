# Cross-Phase Contracts (Phases 8–12)

This document defines how a flow moves from any ETTH source to inference, the WebSocket stream and the frontend, and what each field means along the way.

- The single source of truth in code is `pipeline/canonical_flow.py`.
- The contracts below are enforced by tests in `tests/test_canonical_flow.py`, `test_sensors_*.py`, `test_inference_contract.py`, `test_cross_phase_integration.py`, `test_live_offline_parity.py` and `test_sensor_status_api.py`.
- Every fixture used by those tests is synthetic. They verify software behaviour, not detection quality.

## 1. Canonical event path

```
 PCAP corpus ──► pipeline.flow_reconstruction ──► pipeline.feature_extraction ──► corpus v3 / replay table ─┐
 (Phase 8)        (per-packet metadata)            (FLOW, TLS_STRUCTURAL, JA3, JA4)                        │
                                                                                                          │ REPLAY
 Live capture ──► LiveFlowTracker (same boundaries, direction and IP-length rules; same feature functions) ─┤ LIVE
                                                                                                          │
 Zeek conn/ssl ──► ZeekCorrelator ─────┐                                                                   │ parsers only:
 Suricata EVE ───► SuricataCorrelator ─┼──► canonical flow dict (feature_provenance=SENSOR_AGGREGATE) ──────┤ not wired to
 eBPF JSON ──────► EBPFEventSource ────┘                                                                   │ the stream
                                                                                                          ▼
                     DetectionPipeline.process_flow ──► TargetResolver (SNI / DNS / responder IP)
                                                    ──► InferenceEngine.predict (registry models; schema +
                                                        provenance gate; never reads `label`)
                                                    ──► ETTHStreamEvent (validated) ──► ConnectionManager
                                                        ──► /ws/live-stream ──► frontend (Live Stream)
 Research evaluation (Phase 9/10) reads ONLY corpus v3. Sensor and live flows never enter experiments.
```

## 2. Sources

| Source | Status | Flow statistics | Fingerprints | Connected to the live stream |
|---|---|---|---|---|
| Corpus replay (`data/processed/v3/replay_flows.parquet`) | implemented | ETTH packet features | ETTH JA3 / `ETTH_JA4_V1` | yes (REPLAY) |
| Live capture (Scapy) | implemented. Needs Npcap/libpcap; unavailable on the integration host ("wpcap.dll missing") | ETTH packet features, with parity to offline tested on synthetic packets | ETTH JA3 / `ETTH_JA4_V1` (first segment only) | yes (LIVE) |
| Zeek JSON logs | adapter (log parsing) | sensor aggregates | Zeek ja3 package (standard JA3); FoxIO JA4 | **no** |
| Suricata EVE JSON | adapter (log parsing) | sensor aggregates | Suricata JA3; FoxIO JA4 (≥ 7) | **no** |
| eBPF | JSON adapter only. **No eBPF program, loader or collector is included** | sensor aggregates | as declared by the external collector | **no** |

`GET /api/sensors/status` reports exactly this: `adapter_available`, `ingestion_active`, `connected_to_live_stream`, and live-capture state. An adapter being importable is never reported as a running sensor.

## 3. Field contract

Missing-value rule: a value the source did not observe is absent or `None`. It is never `0`, `""`, `0.0.0.0`, a default protocol, or a value inferred from another field. The event layer lists such fields in `FlowDetails.unobserved_fields`. The numeric value it carries for them is only a display default, and models never see it.

### 3.1 Identity, timing and direction

| Field | Type / unit | Kind | Replay / live | Zeek | Suricata | eBPF |
|---|---|---|---|---|---|---|
| `flow_id` | str | identifier (forbidden as model input) | SHA-256 of pcap hash + 5-tuple + instance / `live_flow_<uuid>` | `uid` | `flow_id` | collector `flow_id`, else a 5-tuple string |
| `sensor_type`, `sensor_record_id` | str | provenance | — | `ZEEK`, `uid` | `SURICATA`, `flow_id` | `EBPF`, `flow_id` |
| `protocol` | `TCP` / `UDP` | raw | as reconstructed | `proto`; other protocols are skipped and counted | `proto`; idem | `protocol` (6/17); idem |
| `forward_endpoint` / `reverse_endpoint` | `ip:port` | raw (forbidden) | forward = **initiator** (first packet's source) | `id.orig_*` / `id.resp_*` | `src_*` / `dest_*` | `saddr:sport` / `daddr:dport` |
| `start_time`, `end_time` | epoch seconds | raw (forbidden) | first / last packet | `ts`, `ts + duration` | `flow.start`, `flow.end` | — |
| `flow_duration` | seconds, float | FLOW feature | last − first packet, unrounded | `duration` | `flow.end − flow.start` (µs). The integer-second `flow.age` is used only as a tagged fallback | `duration_ns / 1e9`, or `end_ns − start_ns` |

### 3.2 Counters and the 15 flow-count features

The counters are `total/forward/reverse_packets` and `total/forward/reverse_bytes`, which feed the 15 `FLOW_COUNT_FEATURES`. All sources compute these features with the same function, `pipeline.feature_extraction.extract_flow_level_features`, wrapped by `canonical_flow.count_features`. Every feature whose input is missing is set to `None`. Rates are `None` when the duration is 0, matching offline (NaN). Phase 11 used rate = count instead, which fabricated a rate.

| Source | `byte_count_semantics` |
|---|---|
| ETTH and live capture | `IP_LENGTH`, from the IP header length, excluding Ethernet padding |
| Zeek | `IP_LENGTH` (`*_ip_bytes`) when present; otherwise `TRANSPORT_PAYLOAD` (`orig_bytes`/`resp_bytes`) |
| Suricata | `UNKNOWN`. Counters are not documented as IP length |
| eBPF | collector-declared, or `UNKNOWN` |

Packet-length, IAT and burst statistics (`PACKET_LENGTH_FEATURES`, `IAT_FEATURES`, `BURST_FEATURES`) exist **only** for the ETTH packet pipeline. No sensor provides them.

### 3.3 TLS fields

| Field | ETTH meaning (model feature) | Zeek / Suricata / eBPF |
|---|---|---|
| `clienthello_present` | ClientHello parsed in the first TCP segment | a TLS handshake was confirmed by the sensor |
| `serverhello_present` | ServerHello parsed | `True` only if ServerHello-derived fields exist (negotiated version, cipher, JA3S, server ALPN). It is never defaulted from `established` |
| `tls_version` | `1.2`/`1.3`, chosen by whether the ClientHello carries `supported_versions` (**offered**) | **never set.** The negotiated version goes to `tls_version_observed` with `tls_version_semantics` `NEGOTIATED` (Zeek/Suricata) or `COLLECTOR_DEFINED` (eBPF) |
| `alpn_value` | first ALPN **offered** by the client | Suricata `client_alpns[0]` (same meaning). Zeek `next_protocol` is the **selected** ALPN and goes to `alpn_negotiated`. eBPF uses `sensor_alpn` |
| `sni`, `sni_present` | SNI present (raw value forbidden as model input) | lowercased server name |
| `ja3_hash` | MD5 of the JA3 string (GREASE removed) | the 32-hex value is kept; a complete JA3 string is MD5-hashed (`ja3_derivation`); anything else is rejected (`ja3_rejected_reason`) |
| `ja4` | `ETTH_JA4_V1` (see §4) | syntax-checked and tagged `ja4_implementation` = `FOXIO_JA4` (Zeek, Suricata) or the declared value / `UNKNOWN` (eBPF) |
| `ja3s_hash` | MD5 of JA3S (not used by any track) | 32-hex or `None` |

### 3.4 Labels and alerts

- `label` is ground truth for corpus rows and `UNKNOWN` for live and sensor flows. It appears only as `provenance.label_ground_truth`.
- The inference engine never reads `label`. A test checks that the score is identical for `MALICIOUS` and `BENIGN` labels.
- Suricata alerts are kept in `sensor_alerts` (signatures) and `sensor_alert_details`, and are surfaced as `provenance.sensor.external_alert_signatures`. They are third-party context only: they are not predictions, ground truth or model inputs, and the governance allow-list contains no `sensor_*` column. A test checks that alerts do not change the score.
- The replay control `threats_only` filters replay rows by the ground-truth label. It is a playback filter, not a prediction.

## 4. JA4: ETTH implementation vs FoxIO

The trained models and corpus v3 use `pipeline.tls_fingerprinting.generate_ja4`. Against the FoxIO specification (`technical_details/JA4.md`) it deviates in six ways:

1. Signature algorithms are **sorted**. FoxIO keeps them in ClientHello order. This affects almost every real ClientHello.
2. Missing SNI is written `n`; FoxIO writes `i`.
3. The version is `13` when `supported_versions` is present, otherwise `12`. FoxIO uses the highest non-GREASE value in `supported_versions`, or else the ClientHello version (`10`, `11`, `s3`, …).
4. With no signature algorithms, ETTH hashes a trailing `_`; FoxIO does not.
5. With no ciphers, ETTH hashes the empty string; FoxIO uses `000000000000`.
6. Counts above 99 are not capped at `99`.

On the FoxIO reference ClientHello (`t13d1516h2_8daaf6152771_e5627efa2ab1`), ETTH produces `t13d1516h2_8daaf6152771_0adf69b4533f` (`tests/test_inference_contract.py`).

Consequence: FoxIO JA4 values from Zeek or Suricata can never match the C/E model vocabularies. Because fingerprint-only models flag most unseen fingerprints (C16), every sensor JA4 would be scored as an unseen fingerprint. Two decisions follow:

- **Inference rule:** a model with a `ja4` input refuses any flow whose `ja4_implementation` is set and differs from `ETTH_JA4_V1`. The flow is SKIPPED with `INCOMPATIBLE_FEATURE_SCHEMA`.
- **Not changed:** `generate_ja4` itself. Changing it would silently redefine the corpus feature and every recorded result. A FoxIO-conformant implementation, and a corpus rebuild with it, are listed as future work.

JA3 is specification-compatible across ETTH, Zeek's ja3 package and Suricata: same field order, GREASE removed from ciphers, extensions and groups. It has not been cross-checked on shared traffic, because no Zeek, Suricata or tshark installation was available.

## 5. Inference compatibility rules (`backend/inference_engine.py`)

A flow is scored only if **all** of the following hold. Otherwise it gets `status=SKIPPED` with an explicit reason, and no value is invented.

1. The track is one of A–E.
2. The fingerprint the track requires (JA3 for B/D, JA4 for C/E) is present.
3. An ACTIVE registry model is loaded for the track: checksum-verified, pickle-free, inside the artefact root.
4. Every model input column is present. A missing value is allowed only where it occurred in training (missing indicator).
5. **Provenance:** if the model uses FLOW or TLS_STRUCTURAL inputs, `feature_provenance` must be absent (legacy corpus rows) or `ETTH_PACKET_FEATURES`. Sensor aggregates are refused.
6. **JA4 implementation:** if the model uses `ja4`, `ja4_implementation` must be absent or `ETTH_JA4_V1`.
7. Live flows marked `live_feature_window_truncated` or `live_flow_split` are refused by flow-feature models.

The rules have these practical effects:

- Sensor flows can be scored only by B_JA3. Their JA3 is usually outside the training vocabulary and is flagged `UNSEEN_CATEGORY:ja3_hash`.
- A/D/E and C/E refuse sensor flows.
- Replaying a capture that was used in training is flagged `IN_SAMPLE_REPLAY`, so such a score is not independent evaluation evidence.
- OOD flags describe input shift. They are not a calibrated probability.
- `confidence` is the distance of the score from the threshold, not a probability of maliciousness.

## 6. Event and WebSocket contract

- `ETTHStreamEvent` (`backend/schemas.py`) is validated before every broadcast. Events must serialise as strict JSON (no NaN or Infinity).
- Additive, optional fields from this integration:
  - `FlowDetails.unobserved_fields`;
  - `ProvenanceDetails.sensor` (`SensorContext`);
  - from Phase 9: `DetectionDetails.model_id`, `model_version`, `research_status`, `calibration_status`, `decision_threshold` and `ood_flags`.
- Older clients that ignore these fields keep working. `frontend/src/types/api.ts` declares them as optional.
- Errors:
  - per-flow errors produce `detection.status=ERROR` with only the exception type (details go to the server log);
  - a replay without data produces `stream.error` and state `ERROR`;
  - live capture without a driver produces `CAPTURE_UNAVAILABLE` and `stream.error`.

## 7. Boundaries

| Layer | Responsibility | Must not |
|---|---|---|
| Sensor ingestion (`backend/event_sources/*_source.py`) | parse, correlate within one sensor, normalise to canonical names, tag provenance, count dropped, duplicate, late and malformed records | compute ETTH packet features, decrypt anything, invent missing values, turn alerts into labels |
| Feature extraction (`pipeline/`) | packet-level reconstruction and features for corpus and live capture | read sensor aggregates as if they were packet features |
| Inference (`backend/inference_engine.py`) | score registry models on compatible inputs; report skips and OOD | train, read `label`, zero-fill, accept provenance mismatches |
| Research evaluation (`ml/`) | corpus v3 only, allow-listed features, capture-grouped splits | use sensor or live flows, or forbidden columns (`ml.features.governance.FORBIDDEN`) |

## 8. Known limitations

- **No runtime path from sensors to the stream.** Sensor adapters are parsers; nothing tails Zeek or Suricata logs or receives eBPF events in the running server. No cross-sensor correlation exists: Zeek, Suricata and eBPF records describing the same connection are not merged.
- **ClientHello reassembly.** ETTH (offline and live) parses only the first TCP segment. Truncated records are flagged (`clienthello_record_truncated`). Large post-quantum ClientHellos therefore often have no ETTH fingerprint, while Zeek and Suricata reassemble.
- **Untested against real tools.** JA3 equality across tools and Suricata byte semantics were not verified against real Zeek, Suricata or tshark output on this host.
- **Live capture timeliness.** Live capture emits flows after FIN/RST, after 120 s idle, or at 300 s (a split, flagged). This matches offline semantics but delays idle flows.
