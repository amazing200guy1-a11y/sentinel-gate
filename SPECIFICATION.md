# SentinelGate Engineering Specification

**Document:** SG-SPEC-001  
**Revision:** 1.0.0  
**Status:** Published  
**Compliance Baseline:** NIST SP 800-207 (Zero Trust Architecture), OWASP LLM Top 10  

---

## 1. Abstract

This document is the normative engineering specification for SentinelGate — a five-layer, zero-trust AI security gateway implemented in Node.js. It defines the threat model, per-layer security contracts, cryptographic primitives, performance requirements, and compliance mappings that govern the system's design and acceptance criteria.

Implementations that satisfy all MUST requirements in this specification are considered conformant. Requirements use RFC 2119 keywords throughout.

---

## 2. Scope

SentinelGate is designed for deployment as an inline HTTP proxy in front of LLM inference endpoints. It is out of scope for:

- TLS termination (handle at the load balancer or reverse proxy layer)
- Model selection or routing
- Response post-processing beyond audit logging

---

## 3. System Threat Model

### 3.1 Adversary Assumptions

| Adversary Class | Capability |
|----------------|------------|
| External attacker | Can craft arbitrary HTTP requests including headers and body |
| Compromised client | Holds a valid API key but attempts privilege escalation |
| Insider threat | Has physical or logical access to the network segment |
| Automated scanner | Issues high-rate malformed or fuzzing requests |

### 3.2 Assets Under Protection

1. LLM inference backend (compute and IP)
2. System prompt confidentiality
3. Stored credentials accessible to the agent
4. Audit log integrity
5. Service availability

### 3.3 Out-of-Scope Threats

- Hardware-level side channels
- Physical access attacks
- Compromise of the Node.js runtime itself

---

## 4. Layer 1 — Cryptographic Authentication

**Module:** `src/crypto_auth.js`

### 4.1 Purpose

Verify the cryptographic identity of every caller before any business logic executes. No caller receives implicit trust based on network position.

### 4.2 Signature Scheme

All requests MUST include four headers:

```
X-API-Key:   <api_key>
X-Nonce:     <uuid_v4>
X-Timestamp: <unix_seconds>
X-Signature: <hmac_hex>
```

The signature is computed as:

```
HMAC-SHA256(client_secret, "POST:/api/process:" + nonce + ":" + timestamp)
```

- Algorithm: HMAC-SHA256 (Node.js `crypto.createHmac`)
- Encoding: Hexadecimal lowercase
- Key material: Per-client secret registered at gateway startup

### 4.3 Requirements

| ID | Requirement |
|----|-------------|
| L1-01 | The gateway MUST reject any request missing one or more of the four required headers with HTTP 401. |
| L1-02 | Signature verification MUST use `crypto.timingSafeEqual` to prevent timing oracle attacks. |
| L1-03 | The gateway MUST reject requests whose `X-Timestamp` differs from server time by more than 300 seconds. |
| L1-04 | The gateway MUST maintain a nonce ring buffer with a minimum 300-second window and MUST reject duplicate nonces within that window with HTTP 401. |
| L1-05 | The nonce ring buffer MUST be implemented as a Map keyed by nonce value with expiry timestamps; expired entries MAY be evicted on any request. |
| L1-06 | The gateway MUST reject requests with an unrecognised `X-API-Key` with HTTP 401 before signature verification. |

### 4.4 Rationale

Timing-safe comparison (L1-02) prevents an attacker from learning partial secret information by measuring response time differences between near-match and far-match signatures — a class of attack documented in CVE-2014-6071 and related disclosures.

---

## 5. Layer 2 — Adaptive Rate Limiter

**Module:** `src/rate_limiter.js`

### 5.1 Purpose

Prevent denial-of-service, token flooding, and resource exhaustion attacks by enforcing per-client, tier-aware request budgets.

### 5.2 Algorithm

Token bucket with continuous-time refill:

```
tokens_available = min(capacity, stored_tokens + elapsed_seconds * refill_rate)
```

On each request:
1. Compute `elapsed = now - last_refill`
2. Add `elapsed * refill_rate` tokens, capped at `capacity`
3. If `tokens_available >= 1`, consume one token and allow
4. Else, return HTTP 429 with `Retry-After` header

### 5.3 Tier Configuration

| Tier | Capacity | Refill Rate | Burst Allowance |
|------|----------|-------------|-----------------|
| standard | 30 | 1 tok/s | 30 requests |
| premium | 150 | 10 tok/s | 150 requests |
| internal | 1,000 | 100 tok/s | 1,000 requests |

### 5.4 Requirements

| ID | Requirement |
|----|-------------|
| L2-01 | The rate limiter MUST assign each client to exactly one tier based on their registered role. |
| L2-02 | The rate limiter MUST use monotonic time (`process.hrtime.bigint`) for token refill calculations to prevent clock-skew manipulation. |
| L2-03 | The gateway MUST return HTTP 429 with a `Retry-After` header when a client exhausts their token budget. |
| L2-04 | Token bucket state MUST be stored per `api_key`, not per IP address, to support clients behind NAT. |

---

## 6. Layer 3 — AI Threat Firewall

**Module:** `src/firewall.js`

### 6.1 Purpose

Detect and block prompt injection, credential exfiltration, jailbreaking, and data exfiltration attacks specific to LLM-integrated systems, as catalogued in the OWASP LLM Top 10.

### 6.2 Rule Set

| Rule ID | Category | Pattern (synopsis) | Score |
|---------|----------|--------------------|-------|
| PROMPT_INJECTION_OVERRIDE | LLM01 | ignore/disregard + (previous\|above\|instructions) | CRITICAL (50) |
| ROLE_BOUNDARY_HIJACK | LLM01 | you are now / pretend you are / act as | HIGH (40) |
| SYSTEM_PROMPT_EXTRACTION | LLM08 | repeat.*(instructions\|prompt) / reveal.*system | HIGH (40) |
| CREDENTIAL_LEAK_OPENAI | LLM06 | sk-[a-zA-Z0-9_-]{24,} | CRITICAL (50) |
| CREDENTIAL_LEAK_GITHUB | LLM06 | ghp_[a-zA-Z0-9]{36} | CRITICAL (50) |
| CREDENTIAL_LEAK_PRIVATE_KEY | LLM06 | BEGIN.*(RSA\|EC\|PRIVATE) KEY | CRITICAL (50) |
| CREDENTIAL_LEAK_AWS | LLM06 | AKIA[0-9A-Z]{16} | CRITICAL (50) |
| MARKDOWN_DATA_EXFILTRATION | LLM02 | !\[.\]\(https?:// (image exfil) | HIGH (40) |
| TOKEN_FLOOD_DOS | LLM04 | single token repeated 500+ times | HIGH (40) |

### 6.3 Shannon Entropy Scanner

In addition to rule-based detection, the firewall computes character-level Shannon entropy on the request body:

```
H = -Σ p(c) * log2(p(c))
```

A score above **4.8 bits/character** triggers a HIGH risk flag. This threshold was calibrated to catch base64-encoded payloads and dense obfuscation while avoiding false positives on natural-language input.

### 6.4 Risk Scoring

Total risk score = sum of scores for all matching rules + entropy flag weight.

| Score Range | Decision |
|------------|----------|
| 0–39 | ALLOW |
| ≥ 40 | BLOCK (HTTP 403) |

### 6.5 Requirements

| ID | Requirement |
|----|-------------|
| L3-01 | Rules MUST be evaluated against the full request body, case-insensitively. |
| L3-02 | The firewall MUST block requests with an aggregate risk score ≥ 40. |
| L3-03 | The firewall MUST compute Shannon entropy on every request body and MUST treat entropy > 4.8 as a HIGH risk flag. |
| L3-04 | Rule evaluation MUST be non-short-circuiting: all rules MUST be scored before the block decision is made. |
| L3-05 | Each blocked request MUST produce an audit log entry identifying which rules triggered and the total score. |

---

## 7. Layer 4 — Execution Sandbox

**Module:** `src/sandbox.js`

### 7.1 Purpose

Enforce least-privilege access control and prevent shell injection, path traversal, and privilege escalation in agent-executed actions.

### 7.2 RBAC Matrix

| Role | Allowed Actions | Denied Actions |
|------|----------------|----------------|
| readonly | read, list, search, get | Any write or execute |
| standard | readonly + write, create, update, delete | execute, admin, shell |
| admin | All standard + execute, admin, shell | — |

### 7.3 Shell Injection Patterns (Blocked for All Roles)

```
; | & ` $ ( ) { }
```

Any action string containing these characters is rejected regardless of role.

### 7.4 Path Traversal Patterns (Blocked for All Roles)

```
../  ..\  /etc/  /proc/  /sys/  C:\Windows\  C:\System
```

### 7.5 Requirements

| ID | Requirement |
|----|-------------|
| L4-01 | The sandbox MUST resolve the caller's role from the authenticated client record set by Layer 1. |
| L4-02 | The sandbox MUST deny any action not in the role's allowed set with HTTP 403. |
| L4-03 | The sandbox MUST scan action strings for shell metacharacters and MUST reject matches regardless of role. |
| L4-04 | The sandbox MUST scan file paths in request parameters for traversal patterns and MUST reject matches regardless of role. |
| L4-05 | Sandbox rejections MUST be logged with the caller's role, the attempted action, and the matched violation pattern. |

---

## 8. Layer 5 — Tamper-Evident Audit Ledger

**Module:** `src/audit_logger.js`

### 8.1 Purpose

Provide a cryptographically verifiable, append-only record of all gateway decisions — allows, blocks, and errors — that survives log tampering attempts and supports forensic replay.

### 8.2 Hash Chain Construction

Each ledger entry contains:

```json
{
  "index": <integer>,
  "timestamp": <ISO-8601>,
  "event": <string>,
  "data": <object>,
  "prev_hash": <sha256_hex | "GENESIS">,
  "hash": <sha256_hex>
}
```

Where:

```
entry.hash = SHA-256(JSON.stringify({
  index, timestamp, event, data, prev_hash
}))
```

### 8.3 Integrity Verification

Chain integrity is verified by iterating all entries and confirming:

1. `entry.prev_hash === previous_entry.hash` (or `"GENESIS"` for index 0)
2. `entry.hash === SHA-256(canonical_fields)`

Any mismatch indicates tampering.

### 8.4 Telemetry

The ledger accumulates request latency samples and exposes percentile statistics:

- p50 (median)
- p95
- p99

Computed using insertion-sort on an in-memory array. Values are reported in milliseconds with three decimal places.

### 8.5 Requirements

| ID | Requirement |
|----|-------------|
| L5-01 | Every gateway decision (allow and deny) MUST produce an audit log entry. |
| L5-02 | Each entry MUST include a `prev_hash` field referencing the SHA-256 hash of the preceding entry. |
| L5-03 | The first entry (index 0) MUST use the string `"GENESIS"` as `prev_hash`. |
| L5-04 | The `verifyChain()` method MUST return `false` if any entry's stored hash does not match a freshly computed hash of its canonical fields. |
| L5-05 | Latency samples MUST be stored per request and MUST be used to compute p50, p95, and p99 percentiles on demand. |

---

## 9. Performance Requirements

| Metric | Requirement | Observed |
|--------|-------------|----------|
| p50 overhead | < 1 ms | 0.225 ms |
| p95 overhead | < 2 ms | 0.590 ms |
| p99 overhead | < 5 ms | 0.934 ms |
| Throughput (single process) | > 1,000 req/s | 3,650 req/s |
| Heap footprint | < 100 MB | 12.13 MB |

All five layers execute sequentially within a single event-loop tick. The budget per layer is approximately 0.04 ms at p50.

---

## 10. NIST SP 800-207 Zero Trust Tenet Mapping

| Tenet | SentinelGate Implementation |
|-------|----------------------------|
| 1. All resources are treated as resources | Every request authenticated regardless of source network |
| 2. All communication is secured | HMAC-signed requests mandatory; plaintext rejected |
| 3. Access granted per-session | Nonce invalidation prevents session token reuse |
| 4. Access determined by dynamic policy | RBAC evaluated on each request; roles are not cached client-side |
| 5. Integrity of assets monitored | Hash-chained ledger with tamper detection |
| 6. Authentication and authorisation are dynamic | Timestamp + nonce window prevents replay and stale token reuse |
| 7. Information collected and used to improve posture | Latency percentiles and block-rate telemetry available via `GET /metrics` |

---

## 11. Test Coverage

The automated test suite (`test/sentinel.test.js`) comprises 25 deterministic tests.

| Group | Tests | Scope |
|-------|-------|-------|
| Layer 1 — Auth | 6 | Valid sig, tampered sig, missing headers, expired timestamp, replay nonce |
| Layer 2 — Rate Limiter | 4 | Burst allowance, sustained load, tier isolation, 429 response |
| Layer 3 — Firewall | 9 | All 9 rule categories + entropy detection |
| Layer 4 — Sandbox | 3 | RBAC allow, deny, shell injection |
| Layer 5 — Audit | 3 | Entry creation, hash-chain verification, percentile computation |

**Acceptance criterion:** All 25 tests MUST pass on `npm test` with exit code 0.

---

## 12. Operational Runbook

### Starting the Gateway

```bash
node src/gateway.js
# Listening on port 8443
```

### Running Tests

```bash
npm test
# Expected: 25/25 PASS
```

### Running the Benchmark

```bash
npm run benchmark
# Expected: p50 < 1 ms, throughput > 1000 req/s
```

### Verifying Ledger Integrity

The gateway exposes `GET /health` which returns:

```json
{
  "status": "operational",
  "ledger_integrity": true,
  "uptime_seconds": <n>
}
```

A `ledger_integrity` value of `false` indicates a tampered or corrupted log and MUST be treated as a security incident.

---

## 13. Revision History

| Revision | Date | Author | Notes |
|----------|------|--------|-------|
| 1.0.0 | 2026-11-02 | Usman Bamidele | Initial publication |
