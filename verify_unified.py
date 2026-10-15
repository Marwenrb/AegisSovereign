"""Smoke test for the AegisSovereign UnifiedRunner (9 planes)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from aegis_sovereign.network_fixtures import ResidentialGeoBackend, DatacenterGeoBackend
from aegis_sovereign.unified_runner import UnifiedRunner
from aegis_sovereign.client_challenge import SignedChallenge
from aegis_sovereign.pow import AegisPoW
import asyncio

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

# Replay protection consumes a valid nonce exactly once.
replay_token = sc.issue(session_id="replay", tls_channel_id="tls")
ok_first, _ = sc.verify_token(replay_token.token, session_id="replay", tls_channel_id="tls")
ok_second, reason_second = sc.verify_token(replay_token.token, session_id="replay", tls_channel_id="tls")
assert ok_first and not ok_second and reason_second == "replay_detected"
print("PASS: replay protection")

# Stateless dynamic PoW roundtrip.
pow_engine = AegisPoW("verify-pow", min_difficulty=1, max_difficulty=2)
challenge = pow_engine.issue(risk_score=0.8, attack_pressure=0.4, subject="verify")
solution = AegisPoW.solve(challenge, max_attempts=100000)
assert pow_engine.verify(challenge.token, solution, subject="verify")[0]
print("PASS: proof-of-work")

# Async single and batch paths preserve order.
async def _async_check():
    one = await runner.assess_request_async(remote_ip="203.0.113.9", surface="public.read")
    batch = await runner.assess_batch_async([
        {"remote_ip": "203.0.113.9", "surface": "public.read"},
        {"remote_ip": "203.0.113.10", "surface": "public.read"},
    ], concurrency=2)
    assert one.audit_event.source == "aegis_sovereign"
    assert len(batch) == 2

asyncio.run(_async_check())
print("PASS: async and batch runner")

print("OK: unified runner smoke test passed")
