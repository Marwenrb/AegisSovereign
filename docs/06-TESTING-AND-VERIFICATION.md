# 06 — Testing, Verification & Quality Assurance

**Lead Architect & Developer:** [Marouan Rabai](https://marwenrabai.com)  
**Maintained by:** [Cristi Labs](https://cristilabs.net)  
**Normative Reference:** `AEGIS-SOVEREIGN-2026`

---

## Quality Assurance Philosophy

AegisSovereign treats test automation as a first-class security property. A false-positive locks legitimate humans out of their accounts; a false-negative enables bot farm takeovers. Every plane is tested with deterministic vectors and execution budgets.

---

## 1. Automated Verification Scripts

The repository includes three standalone verification scripts in the root directory that validate environment contracts without external test runners:

### A. Module Import & Export Verification (`verify_imports.py`)
Validates that all 50+ classes, functions, and symbols export cleanly and that runtime dependencies remain strictly at zero:

```bash
python verify_imports.py
```
**Expected Output:**
```text
version: 3.1.0
ref: AEGIS-SOVEREIGN-2026
imports OK
config database: sqlite:///instance/aegis_sovereign.db
MODULE IMPORT CHECK PASSED
```

### B. Configuration Validation & Secret Redaction (`verify_config.py`)
Validates environment variable hydration, type coercion, bounds checking, and security secret redaction:

```bash
python verify_config.py
```
**Expected Output:**
```text
DB path: sqlite:///instance/aegis_sovereign.db
fail_open threshold: 0.02
JA4 TLS: True
challenge TTL: 5
plane timeout: 0.75
PASS: default config OK
PASS: config_from_dict OK
PASS: env overrides OK
PASS: validation OK
PASS: redaction OK
PASS: failure policy matrix OK
ALL CONFIG TESTS PASSED
```

### C. Unified Runner 9-Plane Integration (`verify_unified.py`)
Executes an end-to-end evaluation cycle across residential and datacenter profiles, verifying log-odds fusion, HMAC challenges, replay nonce protection, Proof-of-Work solving, and async batch evaluation:

```bash
python verify_unified.py
```
**Expected Output:**
```text
decision     : allow
risk_score   : 0.1616
reasons      : ['network_shared_egress', 'low_confidence']
family_scores: {'network': 0.49, 'transport': 0.49, 'client': 0.2, 'identity': 0.1, 'behaviour': 0.13, 'graph': 0.05}
PASS: healthy client -> allow
decision     : challenge
risk_score   : 0.7365
reasons      : ['network_datacenter', 'network_shared_egress', 'client_webdriver', 'integrity_required']
PASS: datacenter+webdriver escalates
PASS: crypto roundtrip
PASS: replay protection
PASS: proof-of-work
PASS: async and batch runner
OK: unified runner smoke test passed
```

---

## 2. Complete Unit Test Suite

Run all 42 automated test cases with Python's standard `unittest` framework:

```bash
python -m unittest discover tests -v
```

Or run via the project `Makefile`:

```bash
# Run all tests
make test

# Run all 3 verification scripts
make verify
```

---

## 3. Writing Custom Test Fixtures

When writing tests or evaluating custom threat models, use the built-in mock network fixtures in `aegis_sovereign.network_fixtures`:

### Simulating Residential Endpoints
```python
import unittest
from aegis_sovereign import UnifiedRunner
from aegis_sovereign.network_fixtures import ResidentialGeoBackend

class TestMySecurityPolicy(unittest.TestCase):
    def test_benign_traffic(self):
        backend = ResidentialGeoBackend()
        runner = UnifiedRunner(geo_backend=backend)
        result = runner.assess_request(
            remote_ip="203.0.113.9",
            claimed_os="Windows 11",
            surface="registration.create"
        )
        self.assertEqual(result.decision, "allow")
        self.assertLess(result.risk_score, 0.35)
```

### Simulating Datacenter Scrapers
```python
from aegis_sovereign.network_fixtures import DatacenterGeoBackend

def test_datacenter_block():
    backend = DatacenterGeoBackend()
    runner = UnifiedRunner(geo_backend=backend)
    result = runner.assess_request(
        remote_ip="198.51.100.23",
        surface="payout",
        webdriver=True
    )
    assert result.decision in {"challenge", "block"}
    assert "network_datacenter" in result.reasons
```
