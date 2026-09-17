# PHASE 7.6 — ETTH TARGET ATTRIBUTION ENGINE DOCUMENTATION

> [!IMPORTANT]
> **Scientific Caveat & Operational Limitation**:
> "Target attribution is an evidence-based association and does **NOT** guarantee application identity."
> Live network traffic is operational engineering data, **NOT** automatically research data.
> Zero TLS decryption is performed; zero packet payload retention is permitted.
> ECH (Encrypted ClientHello), shared CDNs, and multi-tenant IP infrastructure mean attribution must output explicit confidence scores and evidence, or return `UNKNOWN` / `NOT_MATCHED` when metadata is insufficient.

---

## 1. Overview & Architecture

Phase 7.6 integrates the **Target Attribution Engine (`TargetResolver`)** directly into the ETTH detection pipeline:

```
Flow Input (TCP/UDP 5-tuple, TLS ClientHello, IP Metadata)
   ↓
TargetResolver Engine (Hostname Normalization, Subdomain Policy, DNS Correlation)
   ↓
TargetAttribution Object (Status, Confidence 0.0–1.0, Structured Evidence)
   ↓
Target Context & DetectionPipeline (Model Track A–E Inference)
   ↓
ETTHStreamEvent Envelope (with .attribution)
   ↓
WebSocket Broadcast & Target Management UI
```

Attribution evaluation occurs **prior to** inference, ensuring target identity and maliciousness threat assessment remain strictly decoupled.

---

## 2. Evidence Model & Statuses

### Attribution Statuses
- `ATTRIBUTED`: Strong evidence (SNI exact/subdomain match, confidence 0.90–0.98).
- `PROBABLE`: Supporting evidence (time-aware DNS correlation, configured IP match, confidence 0.40–0.75).
- `UNKNOWN`: Insufficient observable metadata or no matching target (confidence 0.0).
- `NOT_MATCHED`: Flow metadata explicitly conflicts with specified target configuration (confidence 0.0).

### Structured Evidence Types
1. `SNI_EXACT`: Observable TLS ClientHello SNI exactly matches target hostname or alias (confidence `0.98`).
2. `SNI_SUBDOMAIN`: Observable SNI is a valid dot-prefixed subdomain of target hostname/alias (confidence `0.90`).
3. `DNS_MATCH`: Destination IP matches a non-stale IP in `DNSCache` resolved from target hostname/alias (confidence `0.75`).
4. `DESTINATION_IP_MATCH`: Destination IP matches target configured IP metadata (confidence `0.40`).
5. `HOSTNAME_MATCH`: Hostname correlation match.
6. `TARGET_METADATA_MATCH`: Target custom metadata match.
7. `CONFLICTING_EVIDENCE`: Observable SNI or DNS correlation conflicts with target (status `NOT_MATCHED`, confidence `0.0`).
8. `NO_EVIDENCE`: No observable SNI, DNS, or IP evidence (status `UNKNOWN`, confidence `0.0`).

---

## 3. Hostname Matching & Subdomain Policy

### Normalization
- Converts hostnames to lowercase.
- Strips leading/trailing whitespace and trailing dots.
- Handles IDNA punycode normalization (`xn--...`).

### Subdomain Validation & Suffix Spoof Rejection
- Exact match: `sni == candidate_host`
- Subdomain match: `sni.endswith("." + candidate_host)`
- **Malicious Suffix Rejection**:
  - `youtube.com.evil.example` vs `youtube.com`
  - `sni` (`youtube.com.evil.example`) does **NOT** equal `candidate_host` (`youtube.com`).
  - `sni` does **NOT** end with `.youtube.com` (ends with `.evil.example`).
  - **Result**: Evaluates as `NOT_MATCHED` with `CONFLICTING_EVIDENCE`. Suffix spoofing is rejected.

---

## 4. Time-Aware Bounded DNS Cache (`DNSCache`)

- Consumes authorized local DNS observations (`POST /api/dns/observations`).
- Thread-safe, bounded capacity (default max 10,000 entries).
- Time-aware with automatic TTL expiration logic. Stale DNS mappings past TTL do not pollute attribution.

---

## 5. QUIC & UDP Protocol Support

- Evaluates flows from both `TCP` and `UDP` (QUIC).
- Consumes observable ClientHello / SNI metadata or DNS correlation without attempting QUIC payload decryption.
- If QUIC metadata is unavailable (e.g. encrypted ClientHello), returns `UNKNOWN` with confidence `0.0`.

---

## 6. Target Aliases

Targets support explicit configuration-driven aliases (e.g., YouTube with `["www.youtube.com", "m.youtube.com", "googlevideo.com"]`). Business logic does not hardcode domain lists.

---

## 7. REST & WebSocket API Extensions

- `POST /api/dns/observations`: Push authorized DNS observations into `target_resolver.dns_cache`.
- `ETTHStreamEvent.attribution`: Emitted events carry full `TargetAttribution` object:

```json
{
  "event_type": "flow.detected",
  "target_id": "target_youtube",
  "session_id": "sess_1789126927_b10a05",
  "attribution": {
    "status": "PROBABLE",
    "confidence": 0.75,
    "target_id": "target_youtube",
    "evidence": [
      {
        "type": "DNS_MATCH",
        "value": "googlevideo.com -> 172.217.14.206",
        "detail": null
      }
    ],
    "resolver_version": "7.6.1"
  }
}
```

---

## 8. Verification Results

- **Backend Pytest**: **144 / 144 passed** (including 25 new Phase 7.6 unit tests).
- **TypeScript**: **0 errors** (`npx tsc --noEmit`).
- **Production Build**: **Successful** (`npm run build`).
- **Manual API Smoke Test**: Verified exact SNI (`0.98`), subdomain SNI (`0.90`), suffix spoof rejection (`NOT_MATCHED`), DNS correlation (`0.75`), and session isolation.
- **Git Status**: 0 commits or pushes executed.
