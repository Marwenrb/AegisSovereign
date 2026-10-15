# 01 — Getting Started with AegisSovereign

**Lead Architect & Developer:** [Marouan Rabai](https://marwenrabai.com)  
**Maintained by:** [Cristi Labs](https://cristilabs.net)  
**Normative Reference:** `AEGIS-SOVEREIGN-2026`

---

## Overview

AegisSovereign is a sovereign-grade, 9-plane anti-automation, bot mitigation, and fraud defense engine. It is engineered with **zero external runtime dependencies** (pure standard-library Python), strict static typing (`mypy --strict`), and sub-millisecond P99 assessment latency.

This guide provides a step-by-step walkthrough to take you from a bare environment to a running system evaluating incoming traffic in production.

---

## Step 1: System Prerequisites

AegisSovereign requires **Python 3.10, 3.11, 3.12, or 3.13**.

### Verify Your Python Installation

```bash
# Linux / macOS
python3 --version

# Windows PowerShell
python --version
```
Ensure the output indicates Python 3.10 or higher.

### Create an Isolated Virtual Environment

#### Linux & macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### Windows PowerShell
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

---

## Step 2: Installation

Install AegisSovereign in editable mode or as a package:

```bash
# Clone the repository
git clone https://github.com/Marwenrb/AegisSovereign.git
cd AegisSovereign

# Install in development mode
pip install -e .
```

### Zero-Dependency Verification
AegisSovereign has no third-party runtime package requirements. You can verify this immediately:

```bash
python verify_imports.py
```

Expected output:
```text
version: 3.1.0
ref: AEGIS-SOVEREIGN-2026
imports OK
config database: sqlite:///instance/aegis_sovereign.db
MODULE IMPORT CHECK PASSED
```

---

## Step 3: Running the System Doctor

AegisSovereign includes a built-in diagnostic utility to verify system configuration, cryptographic integrity, and benchmark latency:

```bash
aegis-sovereign doctor
```

### Diagnostic Output Explained

```text
AegisSovereign doctor v3.1.0 (AEGIS-SOVEREIGN-2026)
attribution ... Cristi Labs / Marouan Rabai
config ........ OK (sqlite:///instance/aegis_sovereign.db)
crypto ........ OK
assessment .... challenge score=0.6690
latency ....... 0.304 ms
planes ........ P1-P9 OK
```

| Check | What It Validates |
| :--- | :--- |
| `attribution` | Verification of authorship and security engineering baseline. |
| `config` | Integrity of environment variables and SQLite state path. |
| `crypto` | HMAC-SHA256 signature generation, validation, and constant-time comparison. |
| `assessment` | Multi-plane log-odds score calibration using test vectors. |
| `latency` | Wall-clock execution time for a full 9-plane assessment cycle (target: < 0.5 ms). |
| `planes` | Health checks across all 9 independent defense planes. |

---

## Step 4: Writing Your First Assessment Script

Create a script named `quick_assess.py`:

```python
"""Quick evaluation script for AegisSovereign."""

from aegis_sovereign import UnifiedRunner
from aegis_sovereign.network_fixtures import ResidentialGeoBackend, DatacenterGeoBackend

# 1. Initialize the runner with a residential test backend
runner = UnifiedRunner(geo_backend=ResidentialGeoBackend())

# 2. Evaluate a legitimate human user
human_result = runner.assess_request(
    remote_ip="203.0.113.9",
    claimed_os="Windows 11",
    claimed_country="FR",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    platform="windows",
    languages=["fr-FR", "en-US"],
    timezone="Europe/Paris",
    screen_geometry="1920x1080x24",
    fonts=["Arial", "Segoe UI", "Calibri"],
    gpu_renderers=["ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"],
    codecs=["h264", "vp9", "av01"],
    input_modality="mouse",
    session_id="session_human_12345",
    tls_channel_id="tls_ch_abc",
    surface="registration.create",
)

print(f"Human Decision  : {human_result.decision}")       # 'allow'
print(f"Human Risk Score: {human_result.risk_score:.4f}")   # ~0.08
print(f"Latency         : {human_result.audit_event.latency_ms:.3f} ms")

# 3. Evaluate an automated headless scraper from a datacenter
datacenter_runner = UnifiedRunner(geo_backend=DatacenterGeoBackend())
bot_result = datacenter_runner.assess_request(
    remote_ip="198.51.100.23",
    claimed_os="Linux",
    claimed_country="US",
    user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0.0.0 Safari/537.36",
    platform="linux",
    languages=["en-US"],
    timezone="UTC",
    screen_geometry="0x0x0",  # Unrealistic headless geometry
    webdriver=True,           # Automation flag exposed
    surface="payout",
)

print(f"Bot Decision    : {bot_result.decision}")         # 'challenge' or 'block'
print(f"Bot Risk Score  : {bot_result.risk_score:.4f}")     # > 0.70
print(f"Triggered Reasons: {bot_result.reasons}")
```

Run the script:
```bash
python quick_assess.py
```

---

## Step 5: Understanding Verdicts and Risk Scores

AegisSovereign outputs calibrated probabilities in `[0.0, 1.0]`. Risk scores are mapped dynamically through the **Response Ladder** (Plane 8) based on action sensitivity and route policy:

| Decision | Risk Range | Description | Recommended System Action |
| :--- | :---: | :--- | :--- |
| `allow` | `0.00 – 0.35` | Benign human profile with coherent evidence. | Permit request immediately without friction. |
| `observe` | `0.35 – 0.50` | Minor anomaly or low-confidence telemetry. | Log enriched telemetry; allow request to proceed. |
| `challenge` | `0.50 – 0.70` | Unverified network egress or client discrepancy. | Issue cryptographic HMAC challenge (`SignedChallenge`). |
| `pow` | `0.55 – 0.85` | High volume or anomalous automation pressure. | Demand computational Proof-of-Work (`AegisPoW`). |
| `stepup` | `0.60 – 0.85` | Sensitive route (`payout`, `recovery`) with elevated risk. | Require WebAuthn/Passkey re-authentication. |
| `throttle` | `0.70 – 0.90` | Repeated bursts exceeding rate-envelope. | Apply async tarpit delays (`100ms – 500ms`). |
| `deception` | `0.85 – 0.95` | Confirmed credential stuffing or scraping campaign. | Return synthetic mock data to exhaust attacker budgets. |
| `block` | `> 0.95` | Hard gate trigger, known exit abuse, or failed crypto proof. | Deterministic HTTP 403 / 429 response. |

---

## Next Steps

- Explore the **[Architecture of the 9 Planes](02-ARCHITECTURE-9-PLANES.md)** for detailed signal-fusion mechanics.
- Learn about **[Cryptographic Challenges](03-CRYPTOGRAPHIC-CHALLENGES.md)** to secure high-value transactions.
- Protect web frameworks using **[Middleware Integration](04-MIDDLEWARE-INTEGRATION.md)**.
