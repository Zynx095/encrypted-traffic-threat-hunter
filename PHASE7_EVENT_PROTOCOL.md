# Phase 7.1 — ETTH Real-Time Event Protocol Specification

## 1. Overview & Conceptual Contract
The Encrypted Traffic Threat Hunter (ETTH) Real-Time Engine provides a hardened, canonical event protocol for streaming network flow analysis over WebSockets (`ws://localhost:8000/ws/live-stream`).

Every event emitted by the backend is validated against Pydantic models ([`backend/schemas.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/backend/schemas.py)) before serialization and broadcasting to frontend consumers ([`frontend/src/types/api.ts`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/frontend/src/types/api.ts)).

---

## 2. Canonical Event Envelope (`ETTHStreamEvent`)

```json
{
  "event_id": "evt_stream_1726071600_a1b2_00001",
  "sequence": 1,
  "timestamp": "2026-09-11T16:20:00.000Z",
  "stream_id": "stream_1726071600_a1b2",
  "source": "DS-008",
  "mode": "REPLAY",
  "event_type": "flow.detected",

  "flow": {
    "flow_id": "93a61f89c02d1b...",
    "protocol": "TCP",
    "forward_endpoint": "192.168.1.100:443",
    "reverse_endpoint": "10.0.0.5:52314",
    "duration": 12.5,
    "total_packets": 100,
    "total_bytes": 50000,
    "packets_per_second": 8.0,
    "bytes_per_second": 4000.0
  },

  "tls": {
    "clienthello_present": true,
    "serverhello_present": true,
    "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
    "ja3s_hash": null,
    "ja4": "t13d151600_8daaf6152771_e8006e86689d",
    "sni_present": true,
    "alpn": "h2"
  },

  "detection": {
    "prediction": "MALICIOUS",
    "threat_score": 0.9421,
    "model_name": "RandomForest",
    "confidence": 0.8842
  },

  "provenance": {
    "dataset_id": "DS-008",
    "source_file": "Zeus.pcap",
    "label_ground_truth": "MALICIOUS",
    "caveat": "Source-confounding limitation: DS-008 malicious vs DS-004 benign split."
  }
}
```

---

## 3. Event Types & Lifecycle

| Event Type (`event_type`) | Category | Description | Payload Section |
| :--- | :--- | :--- | :--- |
| `stream.started` | Lifecycle | Emitted when a new stream session starts or restarts | `metadata` |
| `flow.detected` | Detection | Emitted for every analyzed network flow event | `flow`, `tls`, `detection`, `provenance` |
| `stream.paused` | Lifecycle | Emitted when streaming is temporarily paused | `metadata` |
| `stream.resumed` | Lifecycle | Emitted when streaming resumes from a paused state | `metadata` |
| `stream.completed` | Lifecycle | Emitted when dataset playback reaches completion | `metadata` |
| `stream.stopped` | Lifecycle | Emitted when streaming is stopped by user/server | `metadata` |
| `stream.error` | Error | Emitted when a validation or stream processing error occurs | `metadata.error_message` |

---

## 4. Sequence & Event ID Semantics

1. **Monotonic Sequence Numbers (`sequence`):**
   - Starts at `1` when `stream.started` is dispatched for a given `stream_id`.
   - Increments by `1` monotonically (`1, 2, 3, ...`) for every subsequent message.
   - Resets to `1` whenever a new `stream_id` is created.
   - Duplicate sequence numbers within the same `stream_id` are dropped by the frontend.

2. **Stable Event IDs (`event_id`):**
   - Format: `evt_{stream_id}_{sequence:05d}` for detection events; `evt_{stream_id}_{lifecycle}` for lifecycle events.
   - Remains completely stable across backend emission, WebSocket transit, Zustand store, and React DOM rendering.

---

## 5. Replay Determinism & Mode Distinction

- **REPLAY vs. LIVE:**
  - `mode` is explicitly set to `"REPLAY"` for historical dataset playback.
  - Replay operates deterministically: given the same source dataset, events are processed in fixed, non-randomized order.
  - Speed multipliers (e.g. `0.5x`, `1.0x`, `2.0x`, `5.0x`) adjust inter-arrival timing delays only, never altering event order or payload content.
  - Replay is an engineering mechanism for stream visualization and DOES NOT constitute live capture or real-time network detection proof.

---

## 6. Semantic Absence of Fingerprints

- If a TLS fingerprint attribute (`ja3_hash`, `ja3s_hash`, or `ja4`) is not present in the packet payload or features, it MUST be represented as explicit `null` / `None`.
- Fingerprint values are **NEVER fabricated or guessed**.

---

## 7. Error & Validation Semantics

- Every outbound message is validated via Pydantic model `ETTHStreamEvent.model_validate()`.
- Invalid payloads are caught before socket transmission, logged as validation errors, and dropped to prevent corrupting clients.

---

## 8. Frontend Consumption Rules

- Use custom React hook [`useWebSocket`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/frontend/src/lib/useWebSocket.ts).
- Filter out stale or duplicate sequence numbers per `stream_id`.
- Distinguish lifecycle events (`stream.started`, `stream.paused`, `stream.completed`) from detection events (`flow.detected`).
- Handle optional/null TLS details safely (`ja3_hash || '-'`).
