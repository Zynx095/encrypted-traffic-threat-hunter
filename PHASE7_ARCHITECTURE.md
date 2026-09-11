# Phase 7 — Real-Time Engine Architecture Specification

This document details the read-only architectural inspection and proposed real-time engine design for Phase 7 of the Encrypted Traffic Threat Hunter (ETTH) platform.

---

## 1. Architectural Audit & Answers to Core Questions

### A. FastAPI Application Location
- **Location:** [`backend/main.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/backend/main.py)
- **Structure:** Single-file FastAPI instance initialized as `app = FastAPI(title="Encrypted Traffic Threat Hunter (ETTH) API", ...)`.
- **CORS:** Configured with `CORSMiddleware` allowing `http://localhost:3000`.
- **Current Role:** Exposes REST endpoints serving JSON responses from static artifacts (Parquet files, manifests, CSV fold results).

### B. Existing WebSocket Infrastructure
- **Status:** **Does not exist yet.**
- [`backend/main.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/backend/main.py) contains only `@app.get(...)` REST route decorators.
- No `WebSocket` connections, connection managers, or message broad-casting logic currently exist in the codebase.

### C. Reusable ETTH Flow / Event Schema
- **Status:** **Fully defined in both backend and frontend.**
- **Backend Schemas:**
  - `Flow.to_dict()` in [`pipeline/flow_reconstruction.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/pipeline/flow_reconstruction.py#L140-L172): Captures 5-tuple canonical endpoints, timing (`start_time`, `end_time`, `duration`), packet/byte counts, packet sequences, direction sequences, and TLS attributes (`clienthello_present`, `ja3_hash`, `ja3s_hash`, `ja4`, `alpn`, `sni_present`).
  - `build_feature_record()` in [`pipeline/feature_extraction.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/pipeline/feature_extraction.py#L166-L206): Extracts derived behavioral features (packets/sec, bytes/sec, asymmetry, burst stats, IAT stats).
- **Frontend Types:**
  - `BehavioralFeature` and `ModelSafeFlow` in [`frontend/src/types/api.ts`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/frontend/src/types/api.ts).

### D. Frontend API Client & Service Layer Organization
- **Location:** [`frontend/src/lib/api.ts`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/frontend/src/lib/api.ts)
- **Pattern:** Centralized object `etthApi` exporting domain-specific namespaces (`pilot`, `manifests`, `flows`, `fingerprints`, `datasets`).
- **HTTP Client:** Uses native `fetch` inside a typed `request<T>(path: string)` helper pointing to `import.meta.env.VITE_API_URL || 'http://localhost:8000'`.
- **State Store:** Zustand store [`frontend/src/store/etthStore.ts`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/frontend/src/store/etthStore.ts) wraps `etthApi` calls to manage async loading, error states, and flow data caching.

### E. Live Stream Page / Component Structure
- **Location:** [`frontend/src/pages/LiveStream.tsx`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/frontend/src/pages/LiveStream.tsx)
- **Current Behavior:** Uses pseudo-streaming via `setInterval` every 1200ms calling `etthApi.flows.search({ limit: 15 })`. It randomly shuffles static dataset flows to mock live flow arrival.
- **UI Structure:** Clean, dark-mode terminal style table displaying `Time`, `Flow ID`, `Label` (`THREAT` / `OK`), `JA3`, `SNI`, `Bytes`, with threat filtering toggle and play/pause controls.

### F. Reusable Backend Artifacts for Real-Time Replay
- **Real PCAP Files:**
  - Malware & Benign Samples: [`data/samples/ds003/Gmail.pcap`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/data/samples/ds003/Gmail.pcap) (9.5 MB), [`Tinba.pcap`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/data/samples/ds003/Tinba.pcap) (2.7 MB), [`Zeus.pcap`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/data/samples/ds003/Zeus.pcap) (14.1 MB).
  - Benign Validation PCAPs: [`data/samples/ds004/sample1.pcap`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/data/samples/ds004/sample4.pcap) to `sample6.pcap`.
- **Pre-Processed Behavioral Flow Datasets:**
  - [`data/processed/features/flows_behavioral_features.parquet`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/data/processed/features/flows_behavioral_features.parquet) contains pre-calculated flow records with full sequence arrays.
  - [`data/processed/v2/model_safe/model_safe_dataset.parquet`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/data/processed/v2/model_safe/model_safe_dataset.parquet).
- **Replay Engines Available:**
  1. *PCAP Packet Streamer:* Uses [`FlowReconstructor`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/pipeline/flow_reconstruction.py#L174) with `dpkt` to parse PCAP frames sequentially and emit reconstructed flows.
  2. *Behavioral Flow Replayer:* Reads rows from `flows_behavioral_features.parquet` and streams flow events dynamically with controllable delays (1x, 2x, 5x speed).

### G. Real-Time Model Inference Availability
- **Model Logic:** Defined in [`pipeline/modeling.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/pipeline/modeling.py) (`get_baseline_models()`: LogisticRegression, RandomForest, XGBoost) and [`pipeline/preprocessing.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/pipeline/preprocessing.py).
- **Current State:** Model weights are not currently saved as persistent serialized `.joblib` files under `ml/models/`. However, models can be lightweightly fitted in memory at backend startup using [`data/processed/v2/model_safe/model_safe_dataset.parquet`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/data/processed/v2/model_safe/model_safe_dataset.parquet), or saved during training so live flows streamed over WebSocket can pass through real-time ML inference (yielding threat probability, prediction label, and feature scores).

### H. Dependencies for WebSocket Support
- **Backend:** `websockets>=12.0` added to [`backend/requirements.txt`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/backend/requirements.txt). FastAPI natively supports WebSockets when an ASGI server (uvicorn) and `websockets` package are installed.
- **Frontend:** Standard browser native `WebSocket` API (no third-party dependencies required).

### I. Architectural Conflicts & Duplication
- **Polling vs. WebSockets:** [`frontend/src/pages/LiveStream.tsx`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/frontend/src/pages/LiveStream.tsx) currently polls REST endpoints (`etthApi.flows.search`) using `setInterval`. This mock polling must be cleanly replaced by a WebSocket client hook connecting to `ws://localhost:8000/ws/live-stream`.
- **State Management:** Live stream events are stored in local `useState` in `LiveStream.tsx`. To allow global thread monitoring or alerting across pages, WebSocket state (connection status, streaming rate, live threats, replay controls) should be integrated into `useETTHStore`.

---

## 2. Proposed Phase 7 Architecture

```
                                 +---------------------------------------+
                                 |         Frontend Application          |
                                 |       (React + Vite + Zustand)        |
                                 +------------------+--------------------+
                                                    |
                                    +---------------+---------------+
                                    |                               |
                             HTTP REST Calls                 WebSocket Connection
                             (Metadata / Search)             (Live Stream & Controls)
                                    |                               |
                                    v                               v
                        +----------------------+         +----------------------+
                        | FastAPI REST Routes  |         | WebSocket Endpoint   |
                        |  (/api/flows, etc.)  |         | (/ws/live-stream)    |
                        +----------------------+         +----------+-----------+
                                                                    |
                                                         +----------v-----------+
                                                         |  Connection Manager  |
                                                         +----------+-----------+
                                                                    |
                                                         +----------v-----------+
                                                         | Real-Time Engine     |
                                                         | (Broadcaster & Stream)|
                                                         +----+------------+----+
                                                              |            |
                                      +-----------------------+            +-----------------------+
                                      |                                                            |
                                      v                                                            v
                        +---------------------------+                                +---------------------------+
                        |   Replay Engine Module    |                                |  Inference Pipeline Engine |
                        | (PCAP / Parquet Streamer) |                                | (RandomForest / XGBoost)  |
                        +-------------+-------------+                                +-------------+-------------+
                                      |                                                            |
                                      +-----------------------+------------+-----------------------+
                                                              |
                                                              v
                                              +-------------------------------+
                                              |      Real Data Artifacts      |
                                              | (PCAPs & Parquet Data Files)  |
                                              +-------------------------------+
```

---

## 3. Data Flow & WebSocket Lifecycle

```
Client (Frontend)                                       Server (FastAPI Backend)
       |                                                           |
       |--- WS Connect: ws://localhost:8000/ws/live-stream ------->| (ConnectionManager accepts)
       |<-- WS Message: {"type": "CONNECTED", ...} ----------------|
       |                                                           |
       |--- WS Send: {"action": "START_REPLAY", "speed": 1.0} ---->| (ReplayEngine starts streaming loop)
       |                                                           |
       |                                                           |=== Loop (every N ms based on speed) ===
       |                                                           | 1. Read next flow event from PCAP/Parquet
       |                                                           | 2. Run real-time inference model
       |                                                           | 3. Format LiveFlowEvent schema
       |<-- WS Message: {"type": "FLOW_EVENT", "data": {...}} -----| 
       |                                                           |========================================
       |                                                           |
       |--- WS Send: {"action": "PAUSE_REPLAY"} ------------------>| (ReplayEngine pauses timer)
       |<-- WS Message: {"type": "STREAM_STATE", "state": "PAUSED"}|
       |                                                           |
       |--- WS Disconnect ---------------------------------------->| (ConnectionManager cleans up)
```

---

## 4. Proposed Event & Message Schema

### WebSocket Control Client Message (`ClientMessage`)
```typescript
type ClientMessage =
  | { action: 'START_REPLAY'; dataset_id?: string; speed?: number; threats_only?: boolean }
  | { action: 'PAUSE_REPLAY' }
  | { action: 'RESUME_REPLAY' }
  | { action: 'SET_SPEED'; speed: number }
  | { action: 'SEEK_REPLAY'; position_ratio: number };
```

### WebSocket Server Message (`ServerMessage`)
```typescript
type ServerMessage =
  | { type: 'CONNECTED'; connection_id: string; available_datasets: string[] }
  | { type: 'STREAM_STATE'; state: 'RUNNING' | 'PAUSED' | 'STOPPED'; speed: number }
  | { type: 'FLOW_EVENT'; data: LiveFlowEvent }
  | { type: 'ERROR'; message: string };

interface LiveFlowEvent {
  event_id: string;
  timestamp: string; // ISO-8601 UTC
  flow_id: string;
  source_file?: string;
  
  // Network / 5-tuple
  protocol: 'TCP' | 'UDP';
  forward_endpoint: string;
  reverse_endpoint: string;
  
  // TLS & Fingerprints
  clienthello_present: boolean;
  serverhello_present: boolean;
  ja3_hash?: string;
  ja3s_hash?: string;
  ja4?: string;
  sni_present: boolean;
  alpn?: string;
  
  // Statistical / Behavioral Metrics
  duration: number;
  total_packets: number;
  total_bytes: number;
  packets_per_second: number;
  bytes_per_second: number;
  
  // ML Inference Output
  prediction: 'MALICIOUS' | 'BENIGN' | 'UNKNOWN';
  threat_score: number; // 0.0 to 1.0 probability
  model_name: string;
  confidence: number;
}
```

---

## 5. Replay Engine Design

The **Replay Engine** (`backend/replay_engine.py`) will feature two modes relying exclusively on authentic existing data:

1. **Parquet Streamer Mode (Default):**
   - Loads rows from [`data/processed/features/flows_behavioral_features.parquet`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/data/processed/features/flows_behavioral_features.parquet).
   - Simulates real-time inter-arrival delays using relative flow timestamps or a configurable ticker frequency (e.g. 500ms to 2000ms base tick, adjusted by `speed` multiplier).
2. **PCAP Live Reconstruction Mode:**
   - Reads packets from [`data/samples/ds003/Zeus.pcap`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/data/samples/ds003/Zeus.pcap) or `Gmail.pcap` using `FlowReconstructor`.
   - As flows complete (FIN/RST or timeout flush), the engine extracts features via `extract_flow_level_features` and emits real `LiveFlowEvent` records.

---

## 6. Real-Time Model Inference Pipeline

- A lightweight inference manager (`backend/inference_engine.py`) loads baseline models from [`pipeline/modeling.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/pipeline/modeling.py).
- On engine startup, if serialized model files do not exist in `ml/models/`, it trains a default `RandomForestClassifier` / `XGBClassifier` on [`data/processed/v2/model_safe/model_safe_dataset.parquet`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/data/processed/v2/model_safe/model_safe_dataset.parquet) using leakage-safe features.
- For every emitted live flow event, `inference_engine.predict(flow)` calculates the threat probability and assigns `prediction` (`MALICIOUS` / `BENIGN`) and `threat_score`.

---

## 7. Risks & Scientific Constraints

1. **Zero Data Fabrication:** The stream MUST only emit real flow features constructed from actual dataset PCAPs and Parquet files.
2. **Scientific Caveats Preservation:** Source-confounding warnings (e.g., DS-008 malicious vs DS-004 benign split) must be indicated on live threat alerts.
3. **ASGI Server Threading:** Background replay loops must execute asynchronously (`asyncio.sleep` / non-blocking tasks) so FastAPI WebSocket connection handlers remain fully responsive.

---

## 8. Strategy & Verification Plan

### Automated Verification:
- **Backend Test:** Write pytest script `tests/test_websocket_stream.py` to verify connection handshake, message reception, pause/resume commands, and schema validity.
- **Dependency Test:** Validate WebSocket server startup with uvicorn.

### Manual Verification:
- Open Live Stream UI page at `http://localhost:3000/live-stream`.
- Confirm live flows stream seamlessly over WebSocket.
- Verify pause, play, speed changes, and threat filtering perform without UI stutters.

---

## 9. Exact Files to Create / Modify in Implementation Phase

### Backend Changes:
1. `[MODIFY]` [`backend/requirements.txt`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/backend/requirements.txt) - Add `websockets>=12.0`.
2. `[NEW]` [`backend/ws_manager.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/backend/ws_manager.py) - WebSocket `ConnectionManager` class.
3. `[NEW]` [`backend/replay_engine.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/backend/replay_engine.py) - Parquet & PCAP replay loop streamer.
4. `[NEW]` [`backend/inference_engine.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/backend/inference_engine.py) - Real-time ML inference wrapper.
5. `[MODIFY]` [`backend/main.py`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/backend/main.py) - Register `/ws/live-stream` endpoint and lifecycle manager.

### Frontend Changes:
6. `[NEW]` [`frontend/src/lib/useWebSocket.ts`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/frontend/src/lib/useWebSocket.ts) - React WebSocket hook with auto-reconnect and state management.
7. `[MODIFY]` [`frontend/src/types/api.ts`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/frontend/src/types/api.ts) - Add `LiveFlowEvent` and WebSocket message type definitions.
8. `[MODIFY]` [`frontend/src/store/etthStore.ts`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/frontend/src/store/etthStore.ts) - Add real-time stream status & live threat state.
9. `[MODIFY]` [`frontend/src/pages/LiveStream.tsx`](file:///E:/UserBenchmark/encrypted-traffic-threat-hunter/frontend/src/pages/LiveStream.tsx) - Connect UI controls to WebSocket feed.
