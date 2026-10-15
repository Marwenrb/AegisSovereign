"""Smoke test for the AegisSovereign UnifiedRunner (9 planes)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from aegis_sovereign.network_fixtures import ResidentialGeoBackend, DatacenterGeoBackend
from aegis_sovereign.unified_runner import UnifiedRunner
from aegis_sovereign.client_challenge import SignedChallenge

runner = UnifiedRunner(geo_backend=ResidentialGeoBackend())

# Legitimate residential traffic
res = runner.assess_request(
    remote_ip="203.0.113.9",
    claimed_os="Windows 11",
    claimed_country="FR",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    platform="windows",
    languages=["fr-FR"],
    timezone="Europe/Paris",
    screen_geometry="1920x1080x24",
    fonts=["Arial"],
    gpu_renderers=["ANGLE (NVIDIA)"],
    codecs=["h264"],
    input_modality="mouse",
    session_id="sess_123",
    tls_channel_id="tls_456",
    surface="registration.create",
)
print("decision     :", res.decision)
print("risk_score   :", res.risk_score)
print("reasons      :", res.reasons)
print("family_scores:", res.family_scores)
print("latency_ms   :", res.audit_event.latency_ms)
print("source       :", res.audit_event.source)
assert res.audit_event.source == "aegis_sovereign"
print("PASS: healthy client ->", res.decision)

# Datacenter + webdriver must escalate
runner2 = UnifiedRunner(geo_backend=DatacenterGeoBackend())
res2 = runner2.assess_request(
    remote_ip="198.51.100.23",
    claimed_os="Windows 11",
    claimed_country="US",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120 Safari/537.36",
    platform="windows",
    languages=["en-US"],
    timezone="America/New_York",
    screen_geometry="0x0",
    session_id="sess_456",
    tls_channel_id="tls_789",
    surface="payout",
    webdriver=True,
)
print("decision     :", res2.decision)
print("risk_score   :", res2.risk_score)
print("reasons      :", res2.reasons)
assert res2.risk_score >= res.risk_score, (res2.risk_score, res.risk_score)
print("PASS: datacenter+webdriver escalates")

# Crypto roundtrip (TLS-bound HMAC token)
sc = SignedChallenge(secret_key="unit-test-secret", ttl_seconds=60, buffer_seconds=15)
tok = sc.issue(session_id="s1", tls_channel_id="t1", claims={"role": "login"})
ok, reason = SignedChallenge.verify(
    tok.token, secret_key="unit-test-secret", session_id="s1", tls_channel_id="t1",
    claims={"role": "login"},
)
assert ok, reason
bad, _ = SignedChallenge.verify(
    tok.token, secret_key="unit-test-secret", session_id="s1", tls_channel_id="WRONG",
)
assert not bad
print("PASS: crypto roundtrip")

print("OK: unified runner smoke test passed")
