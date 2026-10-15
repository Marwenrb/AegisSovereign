# AegisSovereign

[![CI](https://github.com/Marwenrb/AegisSovereign/actions/workflows/ci.yml/badge.svg)](https://github.com/Marwenrb/AegisSovereign/actions)
![Python](https://img.shields.io/badge/Python-3.10%E2%80%933.13-blue?logo=python&logoColor=white)
![Deps](https://img.shields.io/badge/Dependencies-Zero%20Core-brightgreen)
![Latency](https://img.shields.io/badge/P99%20Latency-%3C0.5ms-orange)
![Integrity](https://img.shields.io/badge/Integrity-HMAC%20TLS--bound-red)
![Audit](https://img.shields.io/badge/Audit-Merkle%20Hash%20Chain-blueviolet)
![Typing](https://img.shields.io/badge/Typing-Strict%20mypy-purple)
![License](https://img.shields.io/badge/License-Apache--2.0-lightgrey)

**Sovereign-Grade 9-Plane Anti-Automation, Bot Mitigation & Fraud Defense Engine.**

Developed by **[Cristi Labs](https://cristilabs.net)** &bull; Lead Architect & Developer: **[Marouan Rabai](https://marwenrabai.com)**.

AegisSovereign fuses nine independent evidence planes into one calibrated, auditable decision in under half a millisecond. Built on the core doctrine: **Cryptography first, inference second. Cheap for humans, ruinously expensive for bot farms.**

---

## 9 Sovereign Defense Planes

| Plane | Name | Primary Defense Capabilities |
| :--- | :--- | :--- |
| **P1** | **Network Intelligence** | Geolocation, ASN classification, datacenter/proxy/VPN detection, passive OS fingerprinting, RTT roundtrip consistency, shared-egress tracking. |
| **P2** | **Transport Fingerprints** | JA4 TLS client fingerprints, HTTP/3 & QUIC validation, client-hint coherence, post-quantum hybrid freshness. |
| **P3** | **Client Integrity** | Server-verifiable HMAC TLS-bound challenges, screen/codec/GPU coherence checks, cohort population rarity, fingerprint churn defense. |
| **P4** | **Behavioural Kinematics** | Inter-arrival timing entropy, Markov surface transition graphs, pointer kinematics & tremor analysis, touch and keystroke dynamics. |
| **P5** | **Identity & Session** | Passkey/WebAuthn assertions, breached credential screening, cryptographic device session binding, DPoP, step-up enforcement. |
| **P6** | **Biometric Assurance** | Presentation attack detection (PAD), injection detection, anti-deepfake hooks, accessibility protection. |
| **P7** | **Calibrated Decision Engine** | Bounded log-odds ensemble fusion, hard-gating rules, cost-sensitive threshold matrix, shadow mode support. |
| **P8** | **Response Orchestration** | Graduated response ladder: `observe` &rarr; `challenge` &rarr; `PoW` &rarr; `step-up` &rarr; `throttle` &rarr; `deception` &rarr; `block`. |
| **P9** | **Governance & Audit** | Tamper-evident Merkle hash chain, population stability index (PSI) drift monitoring, pseudonymised telemetry, OpenMetrics export. |

---

## Core Design Principles

1. **Cryptography over Inference** &mdash; Server-verifiable cryptographic proofs gate high-value actions; probabilistic inference never overrides a failed proof.
2. **Cost Asymmetry** &mdash; Adaptive Proof-of-Work (PoW) and cryptographic challenges scale attacker compute exponentially while human P99 latency stays sub-millisecond.
3. **No Attacker Oracle** &mdash; Uniform response shapes, withheld internal reason codes, and randomized jitter deny adversary tuning feedback.
4. **Risk-Proportionate Friction** &mdash; Friction scales dynamically with expected loss (`P(abuse) x Loss > Friction`), avoiding blanket blocks that hurt legitimate users.
5. **Layered Independence** &mdash; Nine planes operate independently with circuit-breaker fault isolation; spoofing any single layer cannot flip the aggregate verdict.
6. **Deliberate Failure Policies** &mdash; Explicit per-route `fail-open` or `fail-closed` declarations prevent cascading outages.
7. **Privacy & Accessibility by Design** &mdash; Data minimization, hashed audit trails, retention limits, and zero discrimination against assistive technologies.

```mermaid
flowchart TD
    subgraph Signal Layer
        P1[P1 Network Intel]
        P2[P2 Transport JA4 / QUIC]
        P3[P3 Client Integrity HMAC]
        P4[P4 Behaviour & Kinematics]
        P5[P5 Identity & Breach Screen]
        P6[P6 Biometric Assurance]
    end

    Signal Layer --> F{P7 Log-Odds Fusion}
    F --> R{Hard Gates & Thresholds}
    
    subgraph Action & Governance
        R --> P8[P8 Response Ladder]
        P8 -->|Plan| RES[Observe / Challenge / PoW / StepUp / Tarpit / Block]
        R --> P9[P9 Governance & Merkle Audit Chain]
    end
```

---

## Installation

AegisSovereign runs with **zero mandatory external runtime dependencies** using the standard library for maximum speed, security, and portable deployment.

```bash
pip install aegis-sovereign
```

Or install in development/editable mode:

```bash
git clone https://github.com/Marwenrb/AegisSovereign.git
cd AegisSovereign
pip install -e .
```

---

## Quickstart

### 1. Unified Assessment (Residential vs Datacenter)

```python
from aegis_sovereign import UnifiedRunner
from aegis_sovereign.network_fixtures import ResidentialGeoBackend, DatacenterGeoBackend

runner = UnifiedRunner(geo_backend=ResidentialGeoBackend())

# Legitimate human user
verdict = runner.assess_request(
    remote_ip="203.0.113.9",
    claimed_os="Windows 11",
    claimed_country="FR",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    platform="windows",
    languages=["fr-FR", "en"],
    timezone="Europe/Paris",
    screen_geometry="1920x1080x24",
    fonts=["Arial", "Segoe UI"],
    gpu_renderers=["ANGLE (NVIDIA)"],
    codecs=["h264", "vp9"],
    input_modality="mouse",
    session_id="sess_human_01",
    tls_channel_id="tls_ch_01",
    surface="registration.create",
)
print(verdict.decision)    # allow
print(verdict.risk_score)  # ~0.08
print(verdict.audit_event.latency_ms)  # < 0.5 ms

# Headless / Datacenter Bot
bot_runner = UnifiedRunner(geo_backend=DatacenterGeoBackend())
bot_verdict = bot_runner.assess_request(
    remote_ip="198.51.100.23",
    claimed_os="Windows 11",
    claimed_country="US",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/120.0",
    session_id="sess_bot_02",
    surface="payout",
    webdriver=True,
)
print(bot_verdict.decision)    # challenge or stepup
print(bot_verdict.risk_score)  # ~0.74
```

---

### 2. Cryptographic TLS-Bound HMAC Challenges

Generate server-verifiable integrity tokens bound to session and TLS channel with clock-skew tolerance and replay protection:

```python
from aegis_sovereign.client_challenge import SignedChallenge

challenge_svc = SignedChallenge(secret_key="prod-secret-key", ttl_seconds=60, buffer_seconds=15)

# Issue token on client challenge initiation
token = challenge_svc.issue(session_id="user_sess_1", tls_channel_id="tls_ch_1", claims={"route": "payout"})

# Verify token on subsequent sensitive action
valid, reason = SignedChallenge.verify(
    token.token,
    secret_key="prod-secret-key",
    session_id="user_sess_1",
    tls_channel_id="tls_ch_1",
    claims={"route": "payout"},
)
assert valid is True
```

---

### 3. Adaptive Proof-of-Work (PoW) Engine & Client SDK

Force abusive clients to expend CPU cycles without burdening human visitors:

```python
from aegis_sovereign.pow import AegisPoW

pow_engine = AegisPoW(secret_key="pow-secret-key", ttl_seconds=120)

# Issue dynamic challenge scaled by risk score and attack pressure
challenge = pow_engine.issue(risk_score=0.75, attack_pressure=0.5, subject="registration")

# Client solves puzzle (reference solver or browser SDK)
solution = AegisPoW.solve(challenge)

# Verify solution on incoming payload
valid, status = pow_engine.verify(challenge.token, solution, subject="registration")
assert valid is True
```

Generate the lightweight, CSP-compliant browser snippet:

```python
from aegis_sovereign.client_sdk import generate_client_sdk

js_code = generate_client_sdk(endpoint="/.well-known/aegis/challenge")
```

---

### 4. Tamper-Evident Merkle Audit Hash Chain

Every audit event is cryptographically hashed and linked to an append-only Merkle tree:

```python
from aegis_sovereign.audit_chain import MerkleAuditChain

chain = MerkleAuditChain(max_links=50_000)
link1 = chain.append("evt-1", {"action": "login", "actor": "alice"})
link2 = chain.append("evt-2", {"action": "payout", "actor": "bob"})

# Verify cryptographic continuity across all audit records
assert chain.verify() is True
print("Current Merkle Root:", chain.root())
```

---

## Web Framework Integrations

### FastAPI & Starlette

```python
from fastapi import FastAPI
from aegis_sovereign.middleware import StarletteAegisMiddleware

app = FastAPI()
app.add_middleware(StarletteAegisMiddleware)

@app.post("/api/v1/auth/login")
async def login():
    return {"status": "authenticated"}
```

### Flask

```python
from flask import Flask, request, jsonify
from aegis_sovereign.middleware import flask_guard

app = Flask(__name__)
guard = flask_guard()

@app.before_request
def enforce_aegis():
    verdict = guard(request)
    if verdict and verdict.decision == "block":
        return jsonify({"error": "access_denied"}), 403
```

---

## CLI & Operations

```bash
# Verify environment and system readiness
aegis-sovereign doctor

# Run ultra-fast latency benchmarks
aegis-sovereign benchmark -n 1000

# Inspect active configuration with redacted secrets
aegis-sovereign inspect-config --json

# Run built-in test suite and plane verifications
python verify_imports.py && python verify_config.py && python verify_unified.py
python -m unittest discover tests -v
```

---

## Production Readiness Checklist

- [x] **Zero core third-party dependencies** &mdash; standard library architecture ensures zero supply-chain risk.
- [x] **Sub-millisecond P99 latency** &mdash; fast in-memory bitwise hashing, sharded TTL caches, and O(1) ring buffers.
- [x] **High concurrency & thread safety** &mdash; sharded bucket locks prevent global mutex contention under load.
- [x] **Replay attack protection** &mdash; atomic `ReplayNonceCache` claims prevent token replay.
- [x] **Strict type coverage** &mdash; 100% typed with `mypy --strict`.
- [x] **Comprehensive automated tests** &mdash; 40+ unit and integration tests across all 9 planes.

---

## Security Policy

Security issues should be reported directly to **security@cristilabs.net**. Please review our full [SECURITY.md](SECURITY.md) policy for coordinated disclosure timelines and bug bounty details.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

---

## Credits

- **System Architect & Lead Developer:** **[Marouan Rabai](https://marwenrabai.com)**
- **Engineering Lab & Maintainer:** **[Cristi Labs](https://cristilabs.net)**
- **GitHub Repository:** **[https://github.com/Marwenrb/AegisSovereign](https://github.com/Marwenrb/AegisSovereign)**
