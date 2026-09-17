# PHASE 7.4 — ETTH LIVE CAPTURE ADAPTER

## Architecture Overview

```
PCAP REPLAY  ──────► [ ReplayEventSource ] ──────┐
                                                  ▼
                                         [ EventSource Abstraction ]
                                                  │
LIVE CAPTURE ──────► [ LiveCaptureSource ] ──────┘
  (Scapy/Npcap)    (5-Tuple Aggregator)           │ (Normalized Flow Dict)
                                                  ▼
                                       [ DetectionPipeline ]
                                                  │
                                         [ ETTHStreamEvent ]
                                                  │
                                         [ WebSocket Broadcast ]
                                                  │
                                         [ LiveStream UI ]
```

---

## 1. EventSource Abstraction

The `EventSource` abstract base class (`backend/event_sources/base.py`) decouples raw packet acquisition and dataset replay from the detection pipeline, model internals, and presentation layers.

```python
class EventSource(ABC):
    def __init__(self, mode: str = "REPLAY"):
        self.mode = mode

    @abstractmethod
    async def start(self, **kwargs) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    def get_status(self) -> Dict[str, Any]: ...
```

---

## 2. Live Capture Dependency & Windows Driver Requirements

- **Primary Packet Capture Library**: **Scapy** (v2.7.0).
- **Windows System Requirement**: **Npcap** (or WinPcap) driver installed with Administrator privileges.
- **Graceful Capability Fallback**: If Npcap or Scapy is unavailable, `LiveCaptureSource` transitions to status `CAPTURE_UNAVAILABLE` with clear structured UI diagnostics. No system drivers are installed automatically, and zero fake traffic is generated under fallback.

---

## 3. 5-Tuple Flow Aggregation & Directionality

Packets captured from network interfaces are grouped into bidirectional flows using the canonical 5-tuple:

$$\text{Canonical Key} = \min(\text{src}, \text{dst}) + \max(\text{src}, \text{dst}) + (\text{protocol})$$

- **Directional Tracking**: Tracks `forward_packets`, `reverse_packets`, `forward_bytes`, `reverse_bytes`, `start_time`, and `last_seen`.
- **Endpoint Formatting**: Stores `forward_endpoint` (`IP:Port`) and `reverse_endpoint` (`IP:Port`).

---

## 4. Flow Finalization Policies

A live network flow is finalized and passed to `DetectionPipeline.process_flow()` when any of the following triggers occur:

1. **TCP FIN / RST Flag**: Immediately finalizes completed connection flows.
2. **Idle Timeout**: 15.0 seconds of inactivity after the last observed packet.
3. **Max Flow Duration**: 60.0 seconds of continuous flow activity (prevents unbounded memory growth for long-lived streams).

Finalized flows are evicted from the active tracking table after processing to prevent duplicate event generation.

---

## 5. Observable TLS Metadata & Fingerprinting

- **Unencrypted Handshake Parsing**: Parses unencrypted TLS `ClientHello` (Record 0x16, Handshake 0x01) and `ServerHello` (Handshake 0x02) header extensions.
- **Observable Fields**:
  - `clienthello_present`: `True` if ClientHello observed.
  - `serverhello_present`: `True` if ServerHello observed.
  - `sni_present`: `True` if Server Name Indication extension observed.
  - `alpn`: Extracted Application-Layer Protocol Negotiation value if present.
  - `ja3_hash`: Derivable MD5 hash of TLS ClientHello parameters.
  - `ja3s_hash`: Derivable MD5 hash of TLS ServerHello parameters.
  - `ja4`: Derivable JA4 fingerprint string.
- **Missing Value Policy**: If handshake parameters are unobservable (e.g. non-TLS traffic or missing ClientHello), fields evaluate to `null` / `False`. **Zero fingerprints are fabricated.**

---

## 6. Safety, Privacy & Retained Metadata

> [!CAUTION]
> **Strict Privacy Safeguards**:
> 1. **Zero Payload Decryption**: TLS payloads are never decrypted.
> 2. **Zero Payload Retention**: Packet payloads (`raw(pkt)`) are parsed for headers/handshake extensions only and immediately garbage-collected. No raw packet contents, application data, cookies, or credentials are stored in memory or on disk.

### Retained Metadata Summary
- Network 5-Tuple (IPs, Ports, Protocol)
- Packet counts and byte lengths
- Flow duration and inter-arrival timing
- Unencrypted TLS handshake metadata (SNI, ALPN, JA3/JA3S/JA4 hashes)

---

## 7. Replay vs Live Operational Distinction

| Metric / Dimension | REPLAY Mode | LIVE Mode |
| :--- | :--- | :--- |
| **Data Source** | Research Dataset (e.g. `DS-008`, `DS-004`) | Physical Network Adapter (Scapy/Npcap) |
| **Stream Mode Field** | `mode: "REPLAY"` | `mode: "LIVE"` |
| **Pause / Resume** | Enabled (Dataset index paused/resumed) | Disabled (Network cannot be paused) |
| **Ground-Truth Label** | Scientific Dataset Label (`BENIGN`/`MALICIOUS`) | `UNKNOWN` (Operational inference target) |
| **Scientific Role** | Model training / Fold cross-validation | Real-time engineering demonstration |

> [!WARNING]
> **Scientific Integrity Notice**:
> Live traffic monitoring is an operational engineering capability. Captured live flows are **NOT** automatically merged into scientific research datasets or cross-validation evaluation benchmarks.
