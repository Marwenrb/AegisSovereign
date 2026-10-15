"""Unit tests for extended AegisSovereign modules: audit_chain, pow, resilience, state, behavior, client_sdk, maintenance."""

from __future__ import annotations

import asyncio
import time
import unittest

from aegis_sovereign.audit_chain import MerkleAuditChain, ChainLink
from aegis_sovereign.pow import AegisPoW, PoWChallenge
from aegis_sovereign.resilience import CircuitBreaker
from aegis_sovereign.state import (
    SlidingWindow,
    ShardedTTLCache,
    ReplayNonceCache,
    prefix_for_ip,
    stable_bucket,
)
from aegis_sovereign.behavior import (
    SurfaceTransitionGraph,
    behaviour_score,
    dispersion_ratio,
    fitts_compliance,
    keystroke_risk,
    kinematics_risk,
    shannon_entropy,
    timing_risk,
    touch_risk,
)
from aegis_sovereign.client_sdk import ClientSDK, generate_client_sdk
from aegis_sovereign.maintenance import MaintenanceManager, AsyncMaintenanceManager


class TestAuditChain(unittest.TestCase):
    def test_empty_chain_root(self) -> None:
        chain = MerkleAuditChain()
        self.assertEqual(chain.root(), "0" * 64)
        self.assertTrue(chain.verify())

    def test_append_and_verify(self) -> None:
        chain = MerkleAuditChain(max_links=100)
        link1 = chain.append("evt-1", {"actor": "alice", "action": "login"})
        link2 = chain.append("evt-2", {"actor": "bob", "action": "payout"})

        self.assertEqual(link1.sequence, 0)
        self.assertEqual(link1.previous_hash, "0" * 64)
        self.assertEqual(link2.sequence, 1)
        self.assertEqual(link2.previous_hash, link1.event_hash)

        self.assertTrue(chain.verify())
        self.assertEqual(len(chain.links()), 2)
        self.assertNotEqual(chain.root(), "0" * 64)

    def test_tamper_detection(self) -> None:
        chain = MerkleAuditChain()
        chain.append("evt-1", {"data": "authentic"})
        chain.append("evt-2", {"data": "authentic-2"})
        self.assertTrue(chain.verify())

        # Tamper with an internal link
        chain._links[0] = ChainLink("evt-1", "0" * 64, "tampered_hash_00000000000000000000000000000000000000000000000000000", 0)
        self.assertFalse(chain.verify())

    def test_max_links_pruning(self) -> None:
        chain = MerkleAuditChain(max_links=3)
        for i in range(5):
            chain.append(f"evt-{i}", {"index": i})
        self.assertEqual(len(chain.links()), 3)
        self.assertEqual([link.sequence for link in chain.links()], [0, 1, 2])
        self.assertTrue(chain.verify())


class TestAegisPoW(unittest.TestCase):
    def setUp(self) -> None:
        self.pow = AegisPoW(secret_key="master-pow-secret", ttl_seconds=60, min_difficulty=1, max_difficulty=16)

    def test_issue_and_verify(self) -> None:
        chal = self.pow.issue(risk_score=0.1, subject="user:42")
        self.assertTrue(chal.token.startswith("AEGISPOW.1."))
        self.assertGreaterEqual(chal.difficulty, 1)

        solution = AegisPoW.solve(chal, max_attempts=500_000)
        ok, reason = self.pow.verify(chal.token, solution, subject="user:42")
        self.assertTrue(ok, reason)

    def test_subject_mismatch_fails(self) -> None:
        chal = self.pow.issue(risk_score=0.1, subject="user:42")
        solution = AegisPoW.solve(chal, max_attempts=500_000)
        ok, reason = self.pow.verify(chal.token, solution, subject="user:99")
        self.assertFalse(ok)
        self.assertEqual(reason, "signature_mismatch")

    def test_expiry(self) -> None:
        chal = self.pow.issue(risk_score=0.1, subject="test")
        solution = AegisPoW.solve(chal, max_attempts=500_000)
        ok, reason = self.pow.verify(chal.token, solution, subject="test", now=chal.expires_at + 10)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_insufficient_work(self) -> None:
        chal = self.pow.issue(risk_score=0.9, subject="hard")
        # Deliberately pick an invalid candidate
        invalid_candidate = "not_a_solution_xyz_12345"
        ok, reason = self.pow.verify(chal.token, invalid_candidate, subject="hard")
        self.assertFalse(ok)
        self.assertIn(reason, ("insufficient_work", "signature_mismatch"))

    def test_difficulty_scaling(self) -> None:
        low = self.pow.difficulty_for(risk_score=0.0, attack_pressure=0.0)
        high = self.pow.difficulty_for(risk_score=1.0, attack_pressure=1.0)
        self.assertGreater(high, low)


class TestCircuitBreaker(unittest.TestCase):
    def test_success_path(self) -> None:
        cb = CircuitBreaker[int]("p1_intel", failure_threshold=2, reset_seconds=0.1)
        result = cb.call(lambda: 42, fallback=lambda _: 0)
        self.assertEqual(result, 42)
        state = cb.state()
        self.assertFalse(state.open)
        self.assertEqual(state.failures, 0)

    def test_trips_open_and_resets(self) -> None:
        cb = CircuitBreaker[str]("network_plane", failure_threshold=2, reset_seconds=0.05)

        def failing():
            raise ConnectionError("down")

        # Failure 1
        r1 = cb.call(failing, fallback=lambda _: "fallback_1")
        self.assertEqual(r1, "fallback_1")
        self.assertFalse(cb.state().open)

        # Failure 2 -> trips open
        r2 = cb.call(failing, fallback=lambda _: "fallback_2")
        self.assertEqual(r2, "fallback_2")
        self.assertTrue(cb.state().open)

        # Call while open returns fallback immediately without executing fn
        called = False
        def should_not_run():
            nonlocal called
            called = True
            return "unexpected"

        r3 = cb.call(should_not_run, fallback=lambda _: "fast_fallback")
        self.assertEqual(r3, "fast_fallback")
        self.assertFalse(called)

        # Wait for reset period
        time.sleep(0.06)
        r4 = cb.call(lambda: "recovered", fallback=lambda _: "fail")
        self.assertEqual(r4, "recovered")
        self.assertFalse(cb.state().open)


class TestStatePrimitives(unittest.TestCase):
    def test_sliding_window(self) -> None:
        win = SlidingWindow[str](window_seconds=1.0, max_events=5)
        now = 100.0
        win.add("req1", now=now)
        win.add("req2", now=now + 0.1)
        win.add("req3", now=now + 0.2)

        snap = win.snapshot(now=now + 0.2)
        self.assertEqual(snap.count, 3)
        self.assertAlmostEqual(snap.mean_interval, 0.1, places=3)
        self.assertEqual(win.values(now=now + 0.2), ["req1", "req2", "req3"])

        # Prune with elapsed window
        values = win.values(now=now + 1.5)
        self.assertEqual(values, [])

    def test_sharded_ttl_cache(self) -> None:
        cache = ShardedTTLCache[str](max_entries=10, shards=2)
        now = 1000.0
        cache.set("key1", "val1", ttl_seconds=5.0, now=now)
        cache.set("key2", "val2", ttl_seconds=5.0, now=now)

        self.assertEqual(cache.get("key1", now=now + 1.0), "val1")
        self.assertTrue(cache.contains("key2", now=now + 1.0))

        # Expired
        self.assertIsNone(cache.get("key1", now=now + 10.0))
        self.assertFalse(cache.contains("key1", now=now + 10.0))

        # Pop
        cache.set("key3", "val3", ttl_seconds=5.0, now=now)
        self.assertEqual(cache.pop("key3"), "val3")
        self.assertIsNone(cache.get("key3", now=now))

    def test_replay_nonce_cache(self) -> None:
        nonces = ReplayNonceCache(max_entries=100, ttl_seconds=10.0)
        now = 500.0
        self.assertTrue(nonces.claim("nonce-abc-123", now=now))
        # Claiming same nonce again fails
        self.assertFalse(nonces.claim("nonce-abc-123", now=now + 1.0))
        # Empty nonce rejected
        self.assertFalse(nonces.claim(""))
        # After TTL expired, it can be re-claimed
        self.assertTrue(nonces.claim("nonce-abc-123", now=now + 15.0))

    def test_prefix_for_ip(self) -> None:
        self.assertEqual(prefix_for_ip("192.0.2.45"), "192.0.2.0/24")
        self.assertEqual(prefix_for_ip("10.0.0.1", ipv4_prefix=16), "10.0.0.0/16")
        self.assertEqual(prefix_for_ip("2001:db8:85a3::8a2e:370:7334"), "2001:db8:85a3::/64")
        self.assertEqual(prefix_for_ip("invalid-ip"), "invalid/0")

    def test_stable_bucket(self) -> None:
        b1 = stable_bucket("user-session-123", buckets=16)
        b2 = stable_bucket("user-session-123", buckets=16)
        self.assertEqual(b1, b2)
        self.assertGreaterEqual(b1, 0)
        self.assertLess(b1, 16)


class TestBehavior(unittest.TestCase):
    def test_entropy_and_dispersion(self) -> None:
        self.assertEqual(shannon_entropy([]), 0.0)
        self.assertEqual(shannon_entropy([5.0, 5.0, 5.0]), 0.0)
        self.assertGreater(shannon_entropy([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]), 1.0)

        self.assertEqual(dispersion_ratio([]), 0.0)
        self.assertEqual(dispersion_ratio([10.0, 10.0]), 0.0)
        self.assertGreater(dispersion_ratio([1.0, 10.0, 1.0, 10.0]), 0.5)

    def test_timing_risk(self) -> None:
        # Fixed interval has high automation risk
        fixed_intervals = [0.100, 0.100, 0.100, 0.100, 0.100]
        risk = timing_risk(fixed_intervals)
        self.assertGreaterEqual(risk, 0.6)

    def test_surface_transition_graph(self) -> None:
        graph = SurfaceTransitionGraph()
        # Normal flow
        risk_normal = graph.risk(["landing"], "signin")
        self.assertEqual(risk_normal, 0.0)

        # Suspicious direct jump to payout
        risk_suspicious = graph.risk(["landing"], "payout")
        self.assertGreaterEqual(risk_suspicious, 0.8)

    def test_kinematics_and_dynamics(self) -> None:
        self.assertEqual(kinematics_risk([]), 0.0)
        self.assertEqual(touch_risk([]), 0.0)
        self.assertEqual(keystroke_risk([]), 0.0)
        self.assertEqual(fitts_compliance([]), 0.5)

        score, features = behaviour_score(
            inter_arrivals=[0.1, 0.2, 0.15, 0.3],
            history=["landing"],
            target="signin",
        )
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)
        self.assertIn("surface_transition", features)
        self.assertIn("timing_entropy", features)


class TestClientSDK(unittest.TestCase):
    def test_generate_client_sdk(self) -> None:
        snippet = generate_client_sdk(endpoint="/custom/challenge", token_header="X-Custom-Token")
        self.assertIn("/custom/challenge", snippet)
        self.assertIn("X-Custom-Token", snippet)
        self.assertIn("AegisSovereign", snippet)
        self.assertIn("solveAegisPow", snippet)

    def test_client_sdk_class(self) -> None:
        s = ClientSDK.snippet()
        self.assertIn("AegisSovereign", s)


class TestMaintenanceManager(unittest.TestCase):
    def test_run_once_safe(self) -> None:
        called = []
        def ok_cb():
            called.append("ok")

        def err_cb():
            raise RuntimeError("boom")

        def ok_cb2():
            called.append("ok2")

        mgr = MaintenanceManager(callbacks=[ok_cb, err_cb, ok_cb2], interval_seconds=1.0)
        mgr.run_once()
        self.assertEqual(called, ["ok", "ok2"])

    def test_async_manager(self) -> None:
        called = []
        async def run_test():
            mgr = AsyncMaintenanceManager(callbacks=[lambda: called.append(1)], interval_seconds=0.01)
            task = asyncio.create_task(mgr.run())
            await asyncio.sleep(0.03)
            mgr.stop()
            await task
        asyncio.run(run_test())
        self.assertGreater(len(called), 0)


class TestEdgeServer(unittest.TestCase):
    def test_edge_server_health_and_decide(self) -> None:
        import threading
        from urllib.request import Request, urlopen
        import json
        from aegis_sovereign.edge_server import EdgeDecisionServer

        server = EdgeDecisionServer(("127.0.0.1", 0))
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # Test /healthz
            with urlopen(f"http://127.0.0.1:{port}/healthz") as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(data.get("ok"))
                self.assertEqual(data.get("service"), "aegis-sovereign")

            # Test /metrics
            with urlopen(f"http://127.0.0.1:{port}/metrics") as resp:
                metrics = resp.read().decode("utf-8")
                self.assertIn("aegis", metrics)

            # Test /decide
            req_data = json.dumps({"remote_ip": "203.0.113.9", "surface": "signin"}).encode("utf-8")
            req = Request(f"http://127.0.0.1:{port}/decide", data=req_data, headers={"Content-Type": "application/json"})
            with urlopen(req) as resp:
                dec = json.loads(resp.read().decode("utf-8"))
                self.assertIn("decision", dec)
                self.assertIn("risk_score", dec)
        finally:
            server.shutdown()
            server.server_close()


class TestAsyncAndPolicyRuntime(unittest.TestCase):
    def test_async_batch_and_sensitive_fallback_policy(self) -> None:
        from aegis_sovereign.network_fixtures import ResidentialGeoBackend
        from aegis_sovereign.unified_runner import UnifiedRunner

        runner = UnifiedRunner(geo_backend=ResidentialGeoBackend())

        async def run_check() -> None:
            result = await runner.assess_request_async(remote_ip="203.0.113.9", surface="public.read")
            batch = await runner.assess_batch_async([
                {"remote_ip": "203.0.113.9", "surface": "public.read"},
                {"remote_ip": "203.0.113.10", "surface": "public.read"},
            ], concurrency=2)
            self.assertIn(result.decision, {"allow", "challenge", "block"})
            self.assertEqual(len(batch), 2)

        asyncio.run(run_check())
        original = runner.network_intel.assess
        runner.network_intel.assess = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("plane down"))
        closed = runner.assess_request(remote_ip="203.0.113.9", surface="payout")
        open_result = runner.assess_request(remote_ip="203.0.113.9", surface="public.read")
        self.assertEqual(closed.decision, "block")
        self.assertEqual(open_result.decision, "allow")
        runner.network_intel.assess = original


class TestDeception(unittest.TestCase):
    def test_decoy_is_structurally_realistic_and_bounded(self) -> None:
        from aegis_sovereign.deception import DeceptionTarpit

        response = DeceptionTarpit("decoy-secret", minimum_delay_ms=5, maximum_delay_ms=10).decoy(
            subject="bot", risk_score=1.0)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"accepted", response.body)
        self.assertLessEqual(response.delay_ms, 10)
        self.assertEqual(response.headers["X-Aegis-Deception"], "1")


if __name__ == "__main__":
    unittest.main()
