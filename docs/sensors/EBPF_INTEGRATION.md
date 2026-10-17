# Phase 11 — eBPF Kernel Observability Integration Guide

## 1. Overview & Objective
eBPF enables lightweight, in-kernel observability by attaching programs to kernel tracepoints, kprobes, and socket buffers (`sock_ops`, TC, XDP) without patching kernel source or loading out-of-tree kernel modules.

In ETTH, eBPF telemetry provides:
- High-performance, zero-copy packet counting and directional byte volume tracking.
- Operating system process context (attributing socket connections to local `pid` and `comm` process binaries).
- Unencrypted TLS ClientHello extraction (SNI, JA3, JA4) directly from socket ingress before encryption or payload forwarding occurs.

---

## 2. Canonical eBPF Ring Buffer Schema (`EBPFEventContract`)

The ETTH `EBPFEventSource` expects JSON or binary ring-buffer events adhering to the following schema:

```json
{
  "saddr": "192.168.1.100",
  "daddr": "104.16.12.1",
  "sport": 54321,
  "dport": 443,
  "protocol": 6,
  "start_ns": 1729080000000000000,
  "end_ns": 1729080002500000000,
  "duration_ns": 2500000000,
  "bytes_sent": 1500,
  "bytes_recv": 6000,
  "packets_sent": 10,
  "packets_recv": 15,
  "pid": 4321,
  "comm": "curl",
  "tls_sni": "api.example.com",
  "ja3_hash": "6734f37431670b3ab4292b8f60f29984",
  "ja4": "t13d1516h2_8daaf6152771_012e83626249",
  "alpn": "h2"
}
```

### Transformation & Normalization Rules:
1. **Timestamp Conversion**: `duration_ns` is divided by `1e9` to convert kernel nanoseconds into standard floating-point seconds.
2. **Process Attribution**: `pid` and `comm` are preserved in flow metadata to assist SOC threat hunters.
3. **Non-Fabrication Policy**: If an eBPF collector lacks a TLS parser probe, `ja3_hash`, `ja4`, and `sni` evaluate to `None`. No synthetic hashes are injected.

---

## 3. Platform Limitations & System Requirements

> [!WARNING]
> **Operating System & Privilege Requirements**:
> - **Supported OS**: Linux (Kernel >= 5.8 with BTF `/sys/kernel/btf/vmlinux`).
> - **Privileges**: Root (`uid 0`) or `CAP_BPF` + `CAP_NET_ADMIN` capabilities.
> - **Windows Environments**: Native kernel attachment is unsupported. When running on Windows, `detect_ebpf_capability()` cleanly returns `available: false` with detailed operational diagnostics. To run on Windows workstations, deploy the eBPF collector inside WSL2 or an Ubuntu VM streaming telemetry over HTTP/WebSocket to the ETTH API.

---

## 4. Ingestion Usage

```python
from backend.event_sources.ebpf_source import EBPFEventSource

ebpf_source = EBPFEventSource()
await ebpf_source.start()

# Consume raw ring buffer JSON line
flow = ebpf_source.parse_line(raw_ring_buffer_line)
if flow:
    # Process through ETTH DetectionPipeline
    event = detection_pipeline.process_flow(flow, track="A_FLOW")
```
