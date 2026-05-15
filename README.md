<div align="center">

<img src="https://zentricprotocol.com/og.png" alt="Zentric Protocol" width="100%">

<br/><br/>

# ZENTRIC PROTOCOL

**PII Integrity · Deterministic Infrastructure · Secure Protocol**

[![Status](https://raw.githubusercontent.com/ZentricProtocol/zentricprotocol/main/badges/status.svg)](https://zentricprotocol.com)
[![Latency](https://raw.githubusercontent.com/ZentricProtocol/zentricprotocol/main/badges/latency.svg)](https://zentricprotocol.com)
[![Precision](https://raw.githubusercontent.com/ZentricProtocol/zentricprotocol/main/badges/precision.svg)](https://zentricprotocol.com)
[![GDPR](https://img.shields.io/badge/GDPR-Art.30_compliant-F5F5F5?style=flat-square&labelColor=0A0A0A)](https://zentricprotocol.com)
[![EU AI Act](https://img.shields.io/badge/EU_AI_Act-§52_compliant-F5F5F5?style=flat-square&labelColor=0A0A0A)](https://zentricprotocol.com)
[![CCPA](https://img.shields.io/badge/CCPA-§1798.100_compliant-F5F5F5?style=flat-square&labelColor=0A0A0A)](https://zentricprotocol.com)

<br/>

*The protocol layer between intent and execution in AI systems.*  
*Every signal examined. Every verdict signed. Nothing passes without record.*

<br/>

[**→ Request Access**](https://zentricprotocol.com) · [**Documentation**](mailto:core@zentricprotocol.com) · [**Integrity Report v1.0**](mailto:core@zentricprotocol.com)

</div>

---

## Repository Scope & Commercial License

This repository exists for **transparency and contribution** — not as a deployable alternative to the hosted service.

| What's in this repo | What's not in this repo |
|---|---|
| Authentication middleware (`/middleware`) | IntegrityGuard detection engine |
| Stripe webhook handler (`/api/webhooks`) | PrivacyGuard NLP classification layer |
| Supabase schema & migrations (`/supabase`) | Signature database (22 injection vectors) |
| API interface contracts & response shapes | Model weights and training data |
| Landing page & documentation (`index.html`) | Audit record signing infrastructure |

**Cloning this repository does not give you access to the Zentric processing service.** The detection engine that inspects prompts, detects PII, and generates signed audit reports runs on Zentric's infrastructure and requires an active license.

### Why publish the middleware?

Because trust is infrastructure. You should be able to verify how authentication works, how your API key is validated, and how subscription state is checked before your requests reach the engine. We believe in auditability at every layer — including our own enforcement code.

### Contributions welcome

We accept contributions to the middleware, webhook handler, and Supabase schema. Open a PR or file an issue. For security-related contributions, see the [Security](#security) section.

### Getting access

| Tier | Price | Requests | Start |
|---|---|---|---|
| **Free Trial** | Free | 500 requests | [Get API key →](https://zentricprotocol.com#api-access) |
| **Growth** | $499/mo | 100,000 req/mo | [Start Growth →](https://buy.stripe.com/6oUeVebMY0Y94mM0blco000) |
| **Enterprise** | $2,500/mo | Unlimited | [Start Enterprise →](https://buy.stripe.com/cNiaEY5oAcGRaLa8HRco001) |

---

## What is Zentric Protocol?

Zentric Protocol is an **infrastructure integrity layer** for AI systems. It sits between your application and your LLM, examining every signal — prompts, responses, user inputs — and returning a cryptographically-signed verdict before execution continues.

It is not a filter. It does not guess. It applies deterministic rules across a standardized pipeline and returns a structured, auditable JSON report for every request.

```
Input Signal
     │
     ▼
┌─────────────────────────────────────────┐
│           ZENTRIC PROTOCOL              │
│                                         │
│  ┌─────────────┐  ┌─────────────────┐  │
│  │IntegrityGuard│→│  PrivacyGuard   │  │
│  │ 22 injection │  │  17 PII types   │  │
│  │  signatures  │  │  7 languages    │  │
│  └─────────────┘  └────────┬────────┘  │
│                             ▼           │
│                    ┌──────────────┐     │
│                    │ ZentricReport│     │
│                    │ UUID+SHA-256 │     │
│                    │  GDPR Art.30 │     │
│                    └──────────────┘     │
└─────────────────────────────────────────┘
     │
     ▼
Verdict + Certificate → Your System
```

---

## Performance Benchmark

Extracted from **Zentric Integrity Report v1.0** — 1,000,000 simulations across all supported attack vectors and entity types.

| Attack Vector | Simulations | Detected | Precision |
|---|---|---|---|
| Prompt Injection (EN) | 187,430 | 187,012 | **99.78%** |
| Prompt Injection (ES/FR/DE) | 134,210 | 133,401 | **99.40%** |
| Base64 / Token Smuggling | 48,900 | 48,761 | **99.72%** |
| Jailbreak multi-vector | 67,340 | 66,988 | **99.48%** |
| Fake SYSTEM override | 39,120 | 39,087 | **99.92%** |
| Role redefinition | 52,000 | 51,743 | **99.51%** |
| **Total** | **529,000** | **528,992** | **99.62%** |

> Full methodology and raw data available on request: [core@zentricprotocol.com](mailto:core@zentricprotocol.com)

---

## The Three Modules

### 01 · IntegrityGuard
Detects prompt injection, jailbreak attempts, and instruction overrides before they reach your LLM.

- 22 catalogued injection signatures
- 7 supported languages (EN, ES, FR, DE, IT, PT, NL)
- Multilingual NLP classification layer
- Mean detection latency: **23.4ms**

### 02 · PrivacyGuard
Identifies and anonymizes PII in prompts and responses. Regional standards treated as first-class entities.

- 17 PII entity types: SSN, NIF, CPF, CURP, IBAN, SWIFT, passport, email, phone, and more
- Regional pattern recognition (EU, US, LATAM)
- Anonymization operators: redact, mask, tokenize, pseudonymize
- Recall rate: **99.71%** across 17 entity types

### 03 · ZentricReport
Every request that passes through the protocol generates a signed, immutable audit record.

```json
{
  "report_id": "zp_01HXYZ...",
  "uuid": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "timestamp_utc": "2026-05-14T22:00:00.000Z",
  "sha256": "e3b0c44298fc1c149afb...",
  "verdict": "CLEARED",
  "integrity": {
    "injection_detected": false,
    "signatures_matched": [],
    "confidence": 0.9998
  },
  "privacy": {
    "pii_detected": true,
    "entities": [
      { "type": "EMAIL", "action": "REDACTED", "position": [42, 61] }
    ]
  },
  "compliance": {
    "gdpr_art30": true,
    "ccpa": true,
    "eu_ai_act_s52": true
  },
  "latency_ms": 21.4
}
```

---

## API Reference

### Authentication

```bash
curl -X POST https://api.zentricprotocol.com/v1/analyze \
  -H "Authorization: Bearer zp_live_..." \
  -H "Content-Type: application/json" \
  -d '{
    "input": "Your prompt or user input here",
    "modules": ["integrity", "privacy"],
    "options": {
      "anonymize": true,
      "language": "auto"
    }
  }'
```

### Response

```json
{
  "status": "ok",
  "verdict": "CLEARED",
  "report": { ... },
  "anonymized_input": "Your prompt or user input here",
  "latency_ms": 23.1
}
```

### Verdict States

| Verdict | Description |
|---|---|
| `CLEARED` | Input passed all checks. Safe to forward to LLM. |
| `BLOCKED` | Injection or high-risk pattern detected. Reject. |
| `ANONYMIZED` | PII found and redacted. Anonymized input returned. |
| `REVIEW` | Low-confidence detection. Human review recommended. |

### SDKs

| Language | Status |
|---|---|
| Python | `pip install zentricprotocol` *(coming Q3 2026)* |
| Node.js | `npm install @zentricprotocol/sdk` *(coming Q3 2026)* |
| REST API | **Available now** |

---

## Compliance Coverage

Zentric Protocol is designed from the ground up for regulated AI deployments.

| Standard | Coverage |
|---|---|
| **GDPR Art. 30** | Record of processing activities generated per request |
| **GDPR Art. 25** | Privacy by design — anonymization as default |
| **CCPA §1798.100** | Consumer data identification and processing record |
| **EU AI Act §52** | Transparency obligations resolved at infrastructure level |
| **SOC 2 Type II** | Audit trail and access controls *(in progress)* |

---

## Pricing

| Tier | Price | Requests | Use Case |
|---|---|---|---|
| **Growth** | $499/mo | 100,000 req/mo | AI-forward companies in production |
| **Enterprise** | $2,500/mo | Unlimited | Regulated industries, EU data residency, dedicated SLA |

[→ Start Growth](https://buy.stripe.com/6oUeVebMY0Y94mM0blco000) · [→ Start Enterprise](https://buy.stripe.com/cNiaEY5oAcGRaLa8HRco001) · [→ Contact for custom](mailto:core@zentricprotocol.com)

---

## Architecture Principles

**Deterministic.** The same input always produces the same verdict. No probabilistic black boxes in the critical path.

**Stateless.** The protocol does not store your data. Each request is processed and returned. The audit record is yours.

**Composable.** Deploy the full stack, a single guard, or wire only the audit layer into existing infrastructure.

**Auditable.** Every verdict is signed with SHA-256, timestamped in UTC, and assigned a UUID. Your compliance team will thank you.

---

## Security

We take the security of this protocol seriously. If you discover a vulnerability, please report it responsibly.

- **Email:** [core@zentricprotocol.com](mailto:core@zentricprotocol.com)
- **Subject:** `[SECURITY] <brief description>`
- **Response SLA:** 48 hours acknowledgement, 7 days resolution target

We do not operate a public bug bounty program at this time. Responsible disclosure is acknowledged in our changelog.

---

## Roadmap

- [x] IntegrityGuard v1.0 — 22 signatures, 7 languages
- [x] PrivacyGuard v1.0 — 17 PII types, EU/US/LATAM
- [x] ZentricReport v1.0 — SHA-256, UUID, GDPR Art.30
- [x] REST API (production)
- [ ] Python SDK — Q3 2026
- [ ] Node.js SDK — Q3 2026
- [ ] Streaming support (SSE) — Q3 2026
- [ ] Webhook callbacks — Q4 2026
- [ ] SOC 2 Type II certification — Q4 2026
- [ ] Self-hosted deployment option — 2027

---

## Contact

| Channel | |
|---|---|
| General | [core@zentricprotocol.com](mailto:core@zentricprotocol.com) |
| Enterprise | [core@zentricprotocol.com](mailto:core@zentricprotocol.com) |
| Security | [core@zentricprotocol.com](mailto:core@zentricprotocol.com) |
| X / Twitter | [@ZentricProtocol](https://x.com/ZentricProtocol) |
| LinkedIn | [Zentric Protocol](https://www.linkedin.com/company/zentricprotocol/) |

---

<div align="center">

**Zentric Protocol · Infrastructure Integrity for the AI Era**

[zentricprotocol.com](https://zentricprotocol.com) · © ZP MMXXVI · v1.0.0

*Built for CTOs who know that trust is infrastructure, not a feature.*

</div>
