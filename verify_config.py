"""Quick smoke test for the AegisSovereign configuration module."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from aegis_sovereign.config_model import SecurityConfig, config_from_dict
from aegis_sovereign.version import AEGIS_REF

assert AEGIS_REF == "AEGIS-SOVEREIGN-2026", AEGIS_REF

# Test 1: default config
c = SecurityConfig.from_environment(env={})
print("DB path:", c.database_url)
assert c.database_url.endswith("aegis_sovereign.db"), c.database_url
print("fail_open threshold:", c.fail_open_threshold)
print("JA4 TLS:", c.enable_ja4_tls)
print("challenge TTL:", c.signed_challenge_ttl_seconds)
print("PASS: default config OK")

# Test 2: from dict
c2 = config_from_dict(
    {
        "fail_open_threshold": 0.05,
        "enable_ja4_tls": False,
        "reputation_feed_urls": ["https://a.example", "https://b.example"],
    }
)
print("fail_open (dict):", c2.fail_open_threshold)
print("PASS: config_from_dict OK")

# Test 3: env overrides (isolated mapping, no process mutation)
c3 = SecurityConfig.from_environment(
    env={"FAIL_OPEN_THRESHOLD": "0.9", "ENABLE_JA4_TLS": "0"}
)
assert c3.fail_open_threshold == 0.9, c3.fail_open_threshold
assert c3.enable_ja4_tls is False
print("PASS: env overrides OK")

# Test 4: validation + redaction
try:
    config_from_dict({"fail_open_threshold": 9.0})
    raise SystemExit("validation should have failed")
except ValueError:
    print("PASS: validation OK")
red = c.to_dict(redact_secrets=True)
assert red["secret_key"] == "***REDACTED***", red["secret_key"]
print("PASS: redaction OK")

print("ALL CONFIG TESTS PASSED")
