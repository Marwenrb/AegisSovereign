"""AegisSovereign tests part 1: crypto, config, coherence."""

from __future__ import annotations

import time
import unittest

from aegis_sovereign import AEGIS_REF, SecurityConfig
from aegis_sovereign.client_challenge import SignedChallenge
from aegis_sovereign.client_signals import (
    ClientSignals,
    CoherenceEngine,
    PopulationRarity,
)
from aegis_sovereign.config_model import config_from_dict


class TestIdentity(unittest.TestCase):
    def test_ref(self) -> None:
        self.assertEqual(AEGIS_REF, "AEGIS-SOVEREIGN-2026")


class TestCrypto(unittest.TestCase):
    def test_roundtrip(self) -> None:
        sc = SignedChallenge(secret_key="s3cret", ttl_seconds=60, buffer_seconds=5)
        tok = sc.issue(session_id="s", tls_channel_id="t", claims={"a": 1})
        self.assertTrue(tok.token.startswith("AEGISINTEG."))
        self.assertEqual(len(tok.token.split(".")), 7)
        ok, reason = SignedChallenge.verify(
            tok.token, secret_key="s3cret", session_id="s",
            tls_channel_id="t", claims={"a": 1},
        )
        self.assertTrue(ok, reason)

    def test_wrong_tls_fails(self) -> None:
        sc = SignedChallenge(secret_key="s3cret", ttl_seconds=60)
        tok = sc.issue(session_id="s", tls_channel_id="t")
        ok, _ = SignedChallenge.verify(
            tok.token, secret_key="s3cret", session_id="s", tls_channel_id="x"
        )
        self.assertFalse(ok)

    def test_wrong_claims_fail(self) -> None:
        sc = SignedChallenge(secret_key="s3cret", ttl_seconds=60)
        tok = sc.issue(session_id="s", tls_channel_id="t", claims={"a": 1})
        ok, reason = SignedChallenge.verify(
            tok.token, secret_key="s3cret", session_id="s",
            tls_channel_id="t", claims={"a": 2},
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "claims_mismatch")

    def test_expiry(self) -> None:
        sc = SignedChallenge(secret_key="s3cret", ttl_seconds=1, buffer_seconds=0)
        tok = sc.issue(session_id="s", tls_channel_id="t")
        ok, reason = SignedChallenge.verify(
            tok.token, secret_key="s3cret", session_id="s",
            tls_channel_id="t", now=tok.expires_at + 5, buffer_seconds=0,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")


class TestConfig(unittest.TestCase):
    def test_defaults(self) -> None:
        c = SecurityConfig.from_environment(env={})
        self.assertTrue(c.database_url.endswith("aegis_sovereign.db"))
        self.assertEqual(c.signed_challenge_ttl_seconds, 5)

    def test_hydrated(self) -> None:
        env = {
            "SIGNED_CHALLENGE_TTL": "9",
            "BEHAVIOUR_ENABLED": "1",
            "ENABLE_PASSKEYS": "0",
            "BIOMETRIC_ENABLED": "1",
            "BIOMETRIC_LEVEL": "IAL1/AAL1",
            "ADAPTIVE_POW": "0",
            "RL_LOGIN": "42",
            "PSI_THRESHOLD": "0.2",
        }
        c = SecurityConfig.from_environment(env=env)
        self.assertEqual(c.signed_challenge_ttl_seconds, 9)
        self.assertTrue(c.behaviour_enabled)
        self.assertFalse(c.enable_passkeys)
        self.assertTrue(c.biometric_enabled)
        self.assertEqual(c.rate_limit_login_per_minute, 42)

    def test_validation(self) -> None:
        with self.assertRaises(ValueError):
            config_from_dict({"fail_open_threshold": 5.0})

    def test_redaction(self) -> None:
        c = SecurityConfig.from_environment(env={})
        self.assertEqual(c.to_dict()["secret_key"], "***REDACTED***")


class TestCoherence(unittest.TestCase):
    def test_no_duplicate_field(self) -> None:
        self.assertFalse(hasattr(ClientSignals(), "languages_list"))

    def test_normalized(self) -> None:
        sig = ClientSignals(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            platform="windows",
            languages=["en-US"],
            timezone="America/New_York",
            screen_geometry="1920x1080x24",
            fonts=["Arial"],
            gpu_renderers=["ANGLE (NVIDIA)"],
            codecs=["h264"],
            input_modality="mouse",
        )
        out = CoherenceEngine().score(sig)
        self.assertLessEqual(out["composite"], 1.0)

    def test_headless(self) -> None:
        bad = ClientSignals(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            platform="windows",
            languages=["fr"],
            timezone="Europe/Paris",
            screen_geometry="0x0",
            fonts=["SF Pro"],
            codecs=[],
            input_modality="mouse",
        )
        out = CoherenceEngine().score(bad)
        self.assertLess(out["per_signal"]["screen_geometry"], 0.5)

    def test_rarity_bounded(self) -> None:
        pop = PopulationRarity(cohort_size=100, anomaly_window=30.0, max_entries=10)
        now = time.time()
        for i in range(20):
            pop.register(f"fp-{i}", now)
        self.assertLessEqual(len(pop._freq), 10)


class TestTelemetry(unittest.TestCase):
    def test_ring_and_percentiles(self) -> None:
        from aegis_sovereign.audit_event import AuditEvent
        from aegis_sovereign.audit_sink import InMemorySink, Telemetry

        sink = InMemorySink(max_events=10, min_score_for_stats=0.0)
        tel = Telemetry(sink=sink)
        ev0 = {"ip": "1.1.1.1", "user_agent": "UA"}
        for i in range(25):
            tel.emit(AuditEvent(
                actor="a", surface="s", decision="allow",
                score=float(i) / 25.0,
                family_scores={"network": 0.1},
                evidence=dict(ev0), latency_ms=float(i),
            ))
        snap = sink.snapshot()
        self.assertEqual(snap["events"], 10)
        self.assertIn("score_p95", snap)
        self.assertIn("score_p99", snap)
        self.assertEqual(ev0["ip"], "1.1.1.1")


class TestRunner(unittest.TestCase):
    def test_planes(self) -> None:
        from aegis_sovereign.client_signals import fingerprint_hash
        from aegis_sovereign.network_fixtures import DatacenterGeoBackend
        from aegis_sovereign.network_fixtures import ResidentialGeoBackend
        from aegis_sovereign.unified_runner import UnifiedRunner

        good = UnifiedRunner(geo_backend=ResidentialGeoBackend()).assess_request(
            remote_ip="203.0.113.9", claimed_os="Windows 11",
            claimed_country="BR", user_agent="Mozilla/5.0 (Windows NT 10.0)",
            platform="windows", languages=["pt-BR"], timezone="America/Sao_Paulo",
            screen_geometry="1920x1080x24", fonts=["Arial"],
            gpu_renderers=["ANGLE"], codecs=["h264"],
            input_modality="mouse", session_id="s1", tls_channel_id="t1",
            surface="registration.create",
        )
        bad = UnifiedRunner(geo_backend=DatacenterGeoBackend()).assess_request(
            remote_ip="198.51.100.23", claimed_os="Windows 11",
            claimed_country="US", user_agent="bot",
            session_id="s2", tls_channel_id="t2",
            surface="payout", webdriver=True,
        )
        self.assertGreaterEqual(bad.risk_score, good.risk_score)
        self.assertLess(good.audit_event.latency_ms, 1000.0)
        self.assertTrue(fingerprint_hash(ClientSignals(user_agent="x")))

    def test_budget(self) -> None:
        import time as _t

        from aegis_sovereign.network_fixtures import ResidentialGeoBackend
        from aegis_sovereign.unified_runner import UnifiedRunner

        runner = UnifiedRunner(geo_backend=ResidentialGeoBackend())
        t0 = _t.perf_counter()
        for i in range(20):
            runner.assess_request(
                remote_ip="203.0.113.9", session_id=f"s{i}",
                tls_channel_id="t", surface="signin",
            )
        avg_ms = (_t.perf_counter() - t0) * 1000.0 / 20.0
        self.assertLess(avg_ms, 30.0)


if __name__ == "__main__":
    unittest.main()

