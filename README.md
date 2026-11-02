# SentinelGate

**Hardened Zero-Trust AI Security Gateway**

![Tests](https://img.shields.io/badge/tests-25%2F25%20PASS-brightgreen?style=flat-square)
![Latency](https://img.shields.io/badge/p50%20latency-0.22ms-blue?style=flat-square)
![Throughput](https://img.shields.io/badge/throughput-3%2C650%20req%2Fs-blue?style=flat-square)
![NIST](https://img.shields.io/badge/NIST-SP%20800--207-orange?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)

---

## Overview

SentinelGate is a production-grade, five-layer AI security gateway that enforces **zero-trust principles** at every request boundary. Every inbound request is independently verified — there is no implicit trust based on network position or caller identity alone.

The gateway is designed for organisations deploying large language model (LLM) inference endpoints who need cryptographic auditability, fine-grained access control, and protection against the OWASP LLM Top 10 threat categories without adding perceptible latency to their inference pipeline.

---

## Architecture

```
Inbound Request
      │
      ▼
┌─────────────────────────────────────────────┐
│  Layer 1 — Cryptographic Authentication     │
│  HMAC-SHA256 · Timing-safe compare          │
│  Nonce deduplication · Replay prevention    │
└─────────────────────┬───────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│  Layer 2 — Adaptive Rate Limiter            │
│  Token-bucket per tier (standard / premium  │
│  / internal) · Microsecond-precision drain  │
└─────────────────────┬───────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│  Layer 3 — AI Threat Firewall               │
│  9 OWASP LLM regex rules · Shannon entropy  │
│  detection · Risk scoring engine            │
└─────────────────────┬───────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│  Layer 4 — Execution Sandbox                │
│  RBAC least-privilege · Shell injection     │
│  blocker · Path traversal prevention        │
└─────────────────────┬───────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│  Layer 5 — Tamper-Evident Audit Ledger      │
│  SHA-256 hash chain · Forensic replay       │
│  p50 / p95 / p99 percentile telemetry       │
└─────────────────────┬───────────────────────┘
                      │
                      ▼
              Authorised Response
```

---

## Layer Reference

| # | Layer | Module | Threat Model |
|---|-------|--------|-------------|
| 1 | Cryptographic Authentication | `src/crypto_auth.js` | Credential theft, replay attacks, timing side-channels |
| 2 | Adaptive Rate Limiter | `src/rate_limiter.js` | DoS, token flooding, resource exhaustion |
| 3 | AI Threat Firewall | `src/firewall.js` | Prompt injection, credential exfiltration, jailbreaking |
| 4 | Execution Sandbox | `src/sandbox.js` | Privilege escalation, path traversal, shell injection |
| 5 | Tamper-Evident Audit Ledger | `src/audit_logger.js` | Log tampering, forensic evasion, compliance gaps |

---

## Benchmark Results

All measurements taken on a single Node.js process, no connection pooling, cold start.

| Metric | Value |
|--------|-------|
| Throughput | **3,650 req/s** |
| p50 latency | **0.225 ms** |
| p95 latency | **0.590 ms** |
| p99 latency | **0.934 ms** |
| Heap | 12.13 MB |
| RSS | 68.53 MB |
| Ledger integrity | INTACT |

Sub-2 ms overhead at p99 means SentinelGate adds negligible latency to any LLM inference backend with p50 response times in the hundreds of milliseconds.

---

## OWASP LLM Top 10 Coverage

| OWASP ID | Threat | Rule |
|----------|--------|------|
| LLM01 | Prompt Injection | `PROMPT_INJECTION_OVERRIDE`, `ROLE_BOUNDARY_HIJACK` |
| LLM02 | Insecure Output Handling | `MARKDOWN_DATA_EXFILTRATION` |
| LLM03 | Training Data Poisoning | Shannon entropy scanner (score ≥ 4.8) |
| LLM04 | Model Denial of Service | `TOKEN_FLOOD_DOS`, Layer 2 rate limiter |
| LLM05 | Supply Chain | Dependency audit in CI (no runtime deps) |
| LLM06 | Sensitive Information Disclosure | `CREDENTIAL_LEAK_OPENAI`, `CREDENTIAL_LEAK_GITHUB`, `CREDENTIAL_LEAK_AWS`, `CREDENTIAL_LEAK_PRIVATE_KEY` |
| LLM07 | Insecure Plugin Design | Layer 4 RBAC + shell injection blocker |
| LLM08 | Excessive Agency | `SYSTEM_PROMPT_EXTRACTION`, sandbox role enforcement |
| LLM09 | Overreliance | Out of scope (evaluation layer) |
| LLM10 | Model Theft | API key gating (Layer 1) |

---

## Live Dashboard

The dashboard is a three-page cockpit that connects to the running gateway via **Server-Sent Events** — every gateway decision streams to the browser in real-time.

| Page | What It Shows |
|------|--------------|
| **Cockpit** | 9-attack simulator (each button POSTs a real attack), live event feed, 4 stat cards, p50/p95/p99 latency bar |
| **Audit Chain** | Full SHA-256 hash chain rendered entry-by-entry, INTACT/COMPROMISED banner, auto-polls every 3s |
| **Architecture** | 5-layer pipeline diagram, live `/health` polling, OWASP LLM Top 10 coverage table |

Start the gateway, then open `dashboard.html` in a browser:

```bash
node src/gateway.js
# open dashboard.html
```

The connection status bar shows **CONNECTED** (live feed active) or **OFFLINE** (gateway not running). The page renders fully in offline mode with `--` placeholders.

---

## Quick Start

```bash
# Install (no production dependencies — Node.js stdlib only)
npm install

# Run all 25 tests
npm test

# Run latency benchmark
npm run benchmark

# Start the gateway on port 8443
node src/gateway.js
```

---

## Sending a Signed Request

SentinelGate uses HMAC-SHA256 request signing. Each request requires:

| Header | Value |
|--------|-------|
| `X-API-Key` | Your API key |
| `X-Nonce` | Unique string per request (UUID recommended) |
| `X-Timestamp` | Unix seconds (must be within ±300 s of server time) |
| `X-Signature` | `HMAC-SHA256(secret, "POST:/api/process:" + nonce + ":" + timestamp)` |

### Demo Credentials

| Agent | API Key | Role |
|-------|---------|------|
| `agent-alpha` | `sg_live_alpha_99x821` | standard |
| `agent-admin` | `sg_live_admin_44z991` | admin |
| `agent-readonly` | `sg_live_readonly_11a332` | readonly |

Secrets are defined in `src/gateway.js` under `REGISTERED_CLIENTS`.

---

## Rate Limit Tiers

| Tier | Capacity | Refill Rate | Use Case |
|------|----------|-------------|----------|
| standard | 30 tokens | 1 tok/s | General agents |
| premium | 150 tokens | 10 tok/s | High-throughput pipelines |
| internal | 1,000 tokens | 100 tok/s | Infrastructure services |

---

## Test Suite

```
npm test
```

25 deterministic unit tests covering:

- HMAC signature validation (valid, tampered, missing, replay)
- Rate limiter burst and sustained load
- Firewall rule hits for all 9 threat categories
- Shannon entropy detection
- RBAC permission matrix (readonly / standard / admin)
- Audit ledger hash-chain integrity
- End-to-end gateway orchestration

---

## NIST SP 800-207 Alignment

SentinelGate implements all seven Zero Trust tenets defined in NIST SP 800-207:

1. **All data sources and computing services are considered resources** — every request, regardless of caller, is treated as potentially hostile.
2. **All communication is secured regardless of network location** — HMAC-signed requests; signatures are mandatory.
3. **Access to individual resources is granted on a per-session basis** — nonce invalidation prevents session reuse.
4. **Access is determined by dynamic policy** — RBAC roles enforced at Layer 4 with least-privilege defaults.
5. **The enterprise monitors and measures the integrity of all assets** — hash-chained audit ledger with tamper detection.
6. **All resource authentication and authorisation is dynamic and strictly enforced** — timestamp + nonce window prevents stale token reuse.
7. **The enterprise collects information about assets, network infrastructure and communications and uses it to improve its security posture** — per-request telemetry fed into the percentile engine.

---

## Project Structure

```
sentinel-gate/
├── src/
│   ├── crypto_auth.js     # Layer 1 — HMAC authentication
│   ├── rate_limiter.js    # Layer 2 — Token-bucket rate limiter
│   ├── firewall.js        # Layer 3 — AI threat firewall
│   ├── sandbox.js         # Layer 4 — RBAC execution sandbox
│   ├── audit_logger.js    # Layer 5 — Hash-chained audit ledger
│   └── gateway.js         # Gateway orchestrator (HTTP on :8443)
├── test/
│   ├── sentinel.test.js   # 25-test automated suite
│   └── benchmark.js       # Latency / throughput benchmark
├── dashboard.html         # Interactive attack-simulator cockpit
├── index.html             # Redirect to dashboard
├── package.json
├── README.md
└── SPECIFICATION.md       # NIST SP 800-207 engineering specification
```

---

## License

MIT — see `LICENSE`.
