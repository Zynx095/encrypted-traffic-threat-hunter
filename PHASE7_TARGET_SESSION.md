# PHASE 7.5 — TARGET & SESSION ABSTRACTION DOCUMENTATION

> [!IMPORTANT]
> **Scientific Caveat & Privacy Boundary**:
> Target/session association does **NOT** imply target attribution.
> Live traffic is operational engineering telemetry, **NOT** automatically research data.
> Zero TLS decryption is performed; zero packet payload retention is permitted.
> Missing TLS metadata, JA3, or JA4 must remain semantically unavailable (`null`).

---

## 1. Overview & Architecture Model

Phase 7.5 shifts ETTH from a stream-centric architecture toward a target/session-centric architecture:

```
Target (e.g. YouTube, GitHub, Custom Hostname)
   ↓
Monitoring Session (REPLAY or LIVE)
   ↓
Observed Flows & Events (5-tuple tracking)
   ↓
Detection Pipeline (Track A-E Inference)
   ↓
ETTHStreamEvent & Telemetry
   ↓
WebSocket Broadcast & Target UI
```

This abstraction allows users to group live capture and replay monitoring sessions under logical targets without making unwarranted scientific claims about flow-to-target attribution (which is explicitly deferred to Phase 7.6).

---

## 2. Target Model

Represents a monitored network target (e.g., website, service, or custom hostname).

```json
{
  "target_id": "target_youtube",
  "name": "youtube",
  "hostname": "youtube.com",
  "display_name": "YouTube",
  "target_type": "WEB",
  "logo": {
    "type": "favicon",
    "reference": "https://www.youtube.com/favicon.ico"
  },
  "enabled": true,
  "created_at": "2026-09-11T22:00:00Z",
  "metadata": { "category": "Streaming Video" }
}
```

### Key Principles
- **Extensible Types**: Supports `WEB`, `CUSTOM`, and future protocol targets.
- **Copyright Safe**: Logos are stored as reference metadata only; no copyrighted assets are committed.
- **No Logic Hardcoding**: Target definitions are strictly data-driven.

---

## 3. Session Model

Represents a single monitoring run associated with a target.

```json
{
  "session_id": "sess_1789125757_c967b7",
  "target_id": "target_youtube",
  "status": "ACTIVE",
  "started_at": "2026-09-11T22:00:00Z",
  "ended_at": null,
  "source_mode": "LIVE",
  "interface_id": "\\Device\\NPF_{...}",
  "flow_count": 1284,
  "threat_count": 3,
  "approved_flow_count": 1267,
  "skipped_flow_count": 14,
  "metadata": {}
}
```

### Session Status Lifecycle
- `CREATED` → `ACTIVE` → `PAUSED` → `STOPPED` / `COMPLETED` / `ERROR`

---

## 4. Repository Abstraction (`TargetRepository` & `SessionRepository`)

- `BaseRepository`: Abstract base class enforcing thread-safe CRUD interface.
- `TargetRepository`: In-memory thread-safe target store with default seed targets (YouTube, GitHub) and soft deletion (`enabled=False`) preserving historical session data.
- `SessionRepository`: In-memory thread-safe monitoring session store with real-time flow/threat counter increments.

---

## 5. REST APIs

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/targets` | List all targets (`include_disabled=true/false`) |
| `POST` | `/api/targets` | Create new target (validates hostname, auto-generates ID) |
| `GET` | `/api/targets/{target_id}` | Get target details |
| `PATCH` | `/api/targets/{target_id}` | Update target metadata/display name |
| `DELETE` | `/api/targets/{target_id}` | Soft-delete target (sets `enabled=False`) |
| `GET` | `/api/targets/{target_id}/sessions` | List monitoring sessions for a target |
| `POST` | `/api/targets/{target_id}/sessions` | Create a monitoring session for a target |
| `GET` | `/api/sessions/{session_id}` | Get session details & flow counters |
| `POST` | `/api/sessions/{session_id}/stop` | Stop an active monitoring session |

---

## 6. WebSocket Protocol Extensions

WebSocket stream controls cleanly support optional `target_id` and `session_id`:

```json
{
  "action": "START_LIVE",
  "interface": "\\Device\\NPF_{...}",
  "track": "A_FLOW",
  "target_id": "target_youtube",
  "session_id": "sess_1789125757_c967b7"
}
```

Backward compatibility is fully preserved: if `target_id` or `session_id` are omitted, streams execute in targetless mode cleanly without error.

---

## 7. Frontend State & UI Components

- **API Client (`etthApi.targets` / `etthApi.sessions`)**: Full TypeScript integration.
- **Route Navigation**: `/targets` added under Command Console navigation group.
- **`TargetManagement.tsx`**:
  - Reusable data-driven target cards with active/disabled badges.
  - "+ Add Target" interactive creation modal.
  - Historical session list showing flow aggregations (total, threats, approved, skipped).

---

## 8. What Phase 7.5 Does NOT Implement

- IP-to-website target attribution (deferred to Phase 7.6).
- DNS / SNI target resolution (deferred to Phase 7.6).
- Approved flow aggregation analytics (deferred to Phase 7.8).
- Database infrastructure (PostgreSQL, Redis, Kafka, Docker).
- TLS decryption or payload retention.

---

## 9. Future Integration (Phase 7.6)

Phase 7.6 will introduce `TargetResolver` into the detection pipeline:

```
EventSource → FlowNormalizer → TargetResolver (Phase 7.6) → Session Context → DetectionPipeline → ETTHStreamEvent
```
