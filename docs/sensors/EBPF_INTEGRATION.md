# Phase 11 — eBPF Event Contract and Adapter

> **Status.** ETTH ships **no eBPF program, loader or collector**. `backend/event_sources/ebpf_source.py` provides:
> - a JSON event contract for an external collector;
> - an adapter that validates those events;
> - a host capability probe.
>
> Validation used only the synthetic fixture `data/fixtures/sensors/ebpf_synthetic.json`. No kernel probe was attached or tested, and the integration host runs Windows. The adapter is not connected to the live stream.

## 1. Capability probe

`detect_ebpf_capability()` never raises. It reports:

| Key | Meaning |
|---|---|
| `adapter_available` | always `True`: the JSON adapter runs on any OS |
| `native_probe_included` | always `False`: ETTH does not provide a probe |
| `available` | whether this host *could* attach native programs: Linux, `/sys/kernel/btf/vmlinux` present, running as root. `CAP_BPF` is not checked |
| `reason`, `os`, `kernel_version`, `btf_available`, `privileges` | diagnostics |

On Windows and macOS, `available` is `False` with an explanatory `reason`.

## 2. Event contract (one JSON object per flow)

```json
{
  "flow_id": "optional collector id (enables duplicate suppression)",
  "saddr": "192.168.1.100", "sport": 54321, "daddr": "104.16.12.1", "dport": 443, "protocol": 6,
  "start_ns": 1729080000000000000, "end_ns": 1729080002500000000,
  "bytes_sent": 1500, "bytes_recv": 6000, "packets_sent": 10, "packets_recv": 15,
  "byte_count_semantics": "IP_LENGTH | LINK_LAYER_FRAME | TRANSPORT_PAYLOAD (optional)",
  "pid": 4321, "comm": "curl",
  "tls_sni": "api.example.com",
  "ja3_hash": "6734f37431670b3ab4292b8f60f29984",
  "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1", "ja4_implementation": "FOXIO_JA4 | ETTH_JA4_V1 (optional)",
  "tls_version": "TLS 1.3", "alpn": "h2"
}
```

## 3. Validation and normalisation rules

| Input | Rule |
|---|---|
| addresses and ports | Both addresses are required, and ports must be 1–65535. Otherwise the event is malformed and counted |
| protocol | Only TCP (6) and UDP (17); others are counted as `unsupported_events` |
| duration | `duration_ns / 1e9`, or `(end_ns − start_ns) / 1e9`, or `flow_duration`. Missing means `None`, and then no rate is computed |
| bytes | `byte_count_semantics` as declared, else `UNKNOWN` |
| `ja3_hash` / `ja3` | Must be an MD5 hex digest or a complete JA3 string (five comma-separated fields), which is MD5-hashed. Anything else is rejected: the fixture's `"771,4865-4866,0-23"` is incomplete |
| `ja4` | Syntax-checked. `ja4_implementation` is the declared value, else `UNKNOWN`. Models trained on ETTH JA4 accept only `ETTH_JA4_V1` |
| `tls_version`, `alpn` | Collector-defined meaning: `tls_version_observed` (`COLLECTOR_DEFINED`) and `sensor_alpn`. They never fill `tls_version` or `alpn_value` |
| `pid`, `comm` | `process_pid`, `process_name`: local context, never a model input |
| duplicates | A repeated collector `flow_id` is suppressed |

All flows are tagged `feature_provenance=SENSOR_AGGREGATE`, so models that use ETTH packet features refuse them.

## 4. Deploying a collector (future work)

A collector would run on Linux ≥ 5.8 with BTF, as root or with `CAP_BPF` + `CAP_NET_ADMIN`. It would aggregate per-socket or per-flow counters, optionally parse the cleartext ClientHello, and emit the JSON above.

Nothing in this repository implements or tests that collector.
