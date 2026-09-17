# PHASE 7.3 — ETTH REPLAY CONTROL & STREAM OBSERVABILITY

## Architecture Overview

```
Replay Engine (State Machine)
      ↓
Detection Pipeline (Model Routing & Evidence)
      ↓
Canonical ETTHStreamEvent (Validated Schema)
      ↓
WebSocket Manager (Multi-Client Broadcast)
      ↓
Frontend Hook & Zustand Store
      ↓
Stream Telemetry UI & Observability
```

---

## 1. Stream State Machine

The ETTH Replay Engine implements an explicit, deterministic state machine with strict validation on state transitions:

```
                  ┌──────────┐
                  │   IDLE   │
                  └────┬─────┘
                       │ START
                       ▼
                  ┌──────────┐
      ┌──────────►│ PLAYING  ├──────────┐
      │           └─┬─────▲──┘          │
      │     PAUSE   │     │   RESUME    │
      │             ▼     │             │
      │           ┌───────┴──┐          │ COMPLETED / STOP
      │           │  PAUSED  │          │
      │           └────┬─────┘          │
      │                │ STOP           │
      │                ▼                ▼
      │           ┌──────────┐    ┌───────────┐
      └───────────┤ STOPPED  │    │ COMPLETED │
                  └──────────┘    └───────────┘
                       ▲                ▲
                       │     ERROR      │
                       └────────┬───────┘
                                │
                          ┌─────┴────┐
                          │  ERROR   │
                          └──────────┘
```

### Valid State Transitions

| From | To | Trigger / Action | Behavior |
| :--- | :--- | :--- | :--- |
| `IDLE` | `PLAYING` | `START_REPLAY` | Generates new `stream_id`, resets counters, launches background `_stream_loop()`. |
| `PLAYING` | `PAUSED` | `PAUSE_REPLAY` | Pauses event loop processing. Emits `stream.paused` and `stream.telemetry`. |
| `PAUSED` | `PLAYING` | `RESUME_REPLAY` | Resumes event loop processing. Emits `stream.resumed` and `stream.telemetry`. |
| `PLAYING` | `COMPLETED` | Dataset Reached End | Emits `stream.completed` and `stream.telemetry`. Stops event generation. |
| `PLAYING` / `PAUSED` | `STOPPED` | `STOP_REPLAY` / Disconnect | Cancels background task cleanly. Emits `stream.stopped` and `stream.telemetry`. |
| `PLAYING` | `ERROR` | Unhandled Pipeline Failure | Emits `stream.error` with metadata details. |

Invalid state transitions (such as `IDLE` -> `PAUSED` or `STOPPED` -> `PAUSED`) are safely rejected without altering system state or throwing uncaught exceptions.

---

## 2. Replay Controls & Speed Adjustment

- **START**: Initializes or restarts stream replay. Protected against duplicate calls while already `PLAYING` (updates speed/track without spawning duplicate tasks or corrupting sequence numbers).
- **PAUSE**: Halts emission of flow events while preserving `current_index` and sequence numbers.
- **RESUME**: Continues replay from the exact paused index position.
- **STOP**: Gracefully halts execution and cancels background tasks.
- **SPEED CONTROLS (0.5x, 1.0x, 2.0x, 5.0x)**: Speed adjustments modify event inter-arrival delays (`delay = 1.0 / speed`) only.

> [!IMPORTANT]
> **Scientific Integrity Constraint**: Speed adjustments change playback timing ONLY. Speed controls NEVER alter event order, feature values, model predictions, ground-truth labels, or fingerprint hashes.

---

## 3. Canonical Telemetry Schema (`StreamTelemetry`)

```json
{
  "stream_id": "stream_1726071600_a1b2c3",
  "mode": "REPLAY",
  "source": "DS-008",
  "state": "PLAYING",
  "selected_track": "A_FLOW",
  "playback_speed": 1.0,
  "total_events": 5420,
  "processed_events": 150,
  "flow_events": 150,
  "malicious_events": 42,
  "benign_events": 108,
  "skipped_events": 0,
  "error_events": 0,
  "events_per_second": 12.4,
  "elapsed_seconds": 12.1,
  "progress_percentage": 2.77,
  "connected_clients": 2,
  "processing_duration_ms": 1.15,
  "inference_duration_ms": 0.78
}
```

---

## 4. Counter Semantics & Metrics Definition

### Lifecycle vs Flow Event Counting
- **Flow Events (`flow_events`)**: Incremented exclusively when a dataset row is processed through the detection pipeline and emitted as `flow.detected`.
- **Lifecycle Events**: (`stream.started`, `stream.paused`, `stream.resumed`, `stream.stopped`, `stream.completed`, `stream.telemetry`) advance the monotonic event `sequence` counter but **do not** increment `flow_events`, `malicious_events`, `benign_events`, or `processed_events`.

### Event Categorization
- `malicious_events`: Count of flow events where model prediction evaluates to `MALICIOUS`.
- `benign_events`: Count of flow events where model prediction evaluates to `BENIGN`.
- `skipped_events`: Count of flow events where detection status evaluates to `SKIPPED` (e.g. missing required fingerprint for Track B/C/D/E).
- `error_events`: Count of flow events where pipeline processing encountered an error (`status == "ERROR"`).

---

## 5. Operational Throughput & Timing Semantics

### Throughput Calculation (`events_per_second`)
- Measured using a rolling window of the last 5.0 seconds of flow event timestamps.
- When fewer than 2 events or less than 0.2 seconds of history exists, returns `null` rather than an unstable or division-by-zero value.

### Application Engineering Latency
- `processing_duration_ms`: Execution duration (in milliseconds) of Python feature extraction, state lookup, and evidence formatting.
- `inference_duration_ms`: Execution duration (in milliseconds) of model inference prediction (`predict_flow` or `predict_ja3`).

> [!WARNING]
> **Scientific & Engineering Distinction**:
> 1. `events_per_second` is an **operational application dispatch throughput rate**, NOT physical network wire bandwidth.
> 2. `processing_duration_ms` / `inference_duration_ms` are **application CPU/GPU execution timings**, NOT physical network transmission latency.
> 3. Operational threat counters represent **runtime predictions**, NOT scientific model-performance evaluation metrics (such as Precision, Recall, F1, PR-AUC, or ROC-AUC derived from 5-fold cross-validation).

---

## 6. Multi-Client Consistency & Clean Shutdown

### Multi-Client Broadcasting
- Every connected WebSocket client subscribes to the single global `ReplayEngine` broadcast channel.
- Handshake telemetry (`stream.telemetry`) is emitted immediately upon WebSocket client connection.
- All connected clients receive identical lifecycle events, flow events, and operational telemetry updates.

### Clean Resource Management
- Sending `STOP_REPLAY`, pausing, completing replay, or client disconnection cleanly cancels background tasks.
- Duplicate `START_REPLAY` calls while `PLAYING` adjust active parameters without spawning duplicate background tasks or orphan threads.
