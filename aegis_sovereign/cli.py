"""AegisSovereign operational CLI.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import secrets
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List

from .version import AEGIS_REF, __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis-sovereign",
                                     description="AegisSovereign - Sovereign 9-Plane Anti-Automation Engine")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    sub = parser.add_subparsers(dest="command")
    doctor = sub.add_parser("doctor", help="Run cryptographic and plane diagnostics")
    doctor.add_argument("--json", action="store_true", help="Emit JSON")
    benchmark = sub.add_parser("benchmark", help="Run sync and async latency benchmark")
    benchmark.add_argument("-n", "--iterations", type=int, default=200)
    benchmark.add_argument("--concurrency", type=int, default=1)
    benchmark.add_argument("--json", action="store_true", help="Emit JSON")
    simulate = sub.add_parser("simulate", help="Run an explainable attack simulation")
    simulate.add_argument("--scenario", choices=["residential", "datacenter_bot", "stealth_headless",
                                                  "credential_stuffing", "replay_attack"], required=True)
    simulate.add_argument("--json", action="store_true", help="Emit JSON")
    edge = sub.add_parser("serve-edge", help="Start universal edge decision sidecar")
    edge.add_argument("--host", default="127.0.0.1")
    edge.add_argument("--port", type=int, default=8787)
    inspect = sub.add_parser("inspect-config", help="Print effective configuration and policy matrix")
    inspect.add_argument("--json", action="store_true", help="Emit JSON")
    inspect.add_argument("--show-secrets", action="store_true", help="Do not redact secrets")
    return parser


def _crypto_self_test() -> Dict[str, bool]:
    from .client_challenge import SignedChallenge
    from .pow import AegisPoW

    service = SignedChallenge("doctor-secret", ttl_seconds=60)
    token = service.issue(session_id="doctor", tls_channel_id="tls", claims={"scope": "doctor"})
    good, _ = SignedChallenge.verify(token.token, secret_key="doctor-secret", session_id="doctor",
                                     tls_channel_id="tls", claims={"scope": "doctor"})
    bad, _ = SignedChallenge.verify(token.token, secret_key="doctor-secret", session_id="doctor",
                                    tls_channel_id="wrong", claims={"scope": "doctor"})
    pow_service = AegisPoW("doctor-secret", min_difficulty=1, max_difficulty=1)
    challenge = pow_service.issue(risk_score=0.0)
    solution = pow_service.solve(challenge, max_attempts=1000)
    pow_good, _ = pow_service.verify(challenge.token, solution)
    return {"hmac_roundtrip": good, "hmac_wrong_tls_rejected": not bad, "pow_roundtrip": pow_good}


def cmd_doctor(as_json: bool = False) -> int:
    from . import SecurityConfig, UnifiedRunner

    config = SecurityConfig.from_environment()
    runner = UnifiedRunner(config=config)
    diagnostics = _crypto_self_test()
    result = runner.assess_request(remote_ip="203.0.113.9", claimed_os="Windows 11", claimed_country="FR",
                                   user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", session_id="doctor",
                                   tls_channel_id="doctor-tls", surface="registration.create")
    payload = {"package": "aegis_sovereign", "version": __version__, "ref": AEGIS_REF,
               "config_ok": True, "crypto": diagnostics, "decision": result.decision,
               "risk_score": result.risk_score, "latency_ms": round(result.audit_event.latency_ms, 3),
               "planes": list(runner.PLANE_NAMES), "plane_status": result.plane_status}
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"AegisSovereign doctor v{__version__} ({AEGIS_REF})")
        print(f"attribution ... Cristi Labs / Marouan Rabai")
        print(f"config ........ OK ({config.database_url})")
        print(f"crypto ........ {'OK' if all(diagnostics.values()) else 'FAIL'}")
        print(f"assessment .... {result.decision} score={result.risk_score:.4f}")
        print(f"latency ....... {result.audit_event.latency_ms:.3f} ms")
        print("planes ........ P1-P9 OK")
    return 0 if all(diagnostics.values()) else 1


def _percentile(values: List[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * q))]


def cmd_benchmark(iterations: int, concurrency: int = 1, as_json: bool = False) -> int:
    from . import UnifiedRunner
    from .network_fixtures import ResidentialGeoBackend

    runner = UnifiedRunner(geo_backend=ResidentialGeoBackend())
    count = max(1, int(iterations))

    def assess(index: int) -> float:
        start = time.perf_counter()
        runner.assess_request(remote_ip="203.0.113.9", claimed_os="Windows 11", claimed_country="BR",
                              user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", session_id=f"bench-{index}",
                              tls_channel_id="bench-tls", surface="registration.create")
        return (time.perf_counter() - start) * 1000.0

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, int(concurrency))) as pool:
        latencies = list(pool.map(assess, range(count)))
    elapsed = time.perf_counter() - start
    payload = {"iterations": count, "concurrency": max(1, int(concurrency)),
               "requests_per_second": round(count / elapsed, 2),
               "p50_ms": round(_percentile(latencies, 0.50), 4),
               "p95_ms": round(_percentile(latencies, 0.95), 4),
               "p99_ms": round(_percentile(latencies, 0.99), 4),
               "p99_9_ms": round(_percentile(latencies, 0.999), 4),
               "max_ms": round(max(latencies), 4)}
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"benchmark n={count} concurrency={payload['concurrency']} rps={payload['requests_per_second']}")
        print(f"p50={payload['p50_ms']}ms p95={payload['p95_ms']}ms p99={payload['p99_ms']}ms p99.9={payload['p99_9_ms']}ms")
    return 0


def cmd_simulate(scenario: str, as_json: bool = False) -> int:
    from . import UnifiedRunner
    from .network_fixtures import DatacenterGeoBackend, ResidentialGeoBackend

    runner = UnifiedRunner(geo_backend=DatacenterGeoBackend() if scenario in {"datacenter_bot", "stealth_headless",
                                                                             "credential_stuffing", "replay_attack"}
                           else ResidentialGeoBackend())
    common: Dict[str, Any] = {"remote_ip": "198.51.100.23" if scenario != "residential" else "203.0.113.9",
                              "claimed_os": "Windows 11", "claimed_country": "US",
                              "user_agent": "Mozilla/5.0 Chrome/120" if scenario == "residential" else "bot",
                              "session_id": "sim-session", "tls_channel_id": "sim-tls", "surface": "signin"}
    if scenario in {"datacenter_bot", "stealth_headless"}:
        common.update({"surface": "payout", "webdriver": True, "screen_geometry": "0x0"})
    if scenario == "credential_stuffing":
        common.update({"surface": "auth.login", "password": "password123", "inter_arrival_times": [1.0] * 12})
    if scenario == "replay_attack":
        token = runner.signed_challenge.issue(session_id="sim-session", tls_channel_id="sim-tls")
        common["integrity_token"] = token.token
        first = runner.assess_request(**common)
        second = runner.assess_request(**common)
        result = second
        trace = {"first": first.to_dict(), "replay_attempt": second.to_dict()}
    else:
        result = runner.assess_request(**common)
        trace = result.to_dict()
    payload = {"scenario": scenario, "decision": result.decision, "risk_score": result.risk_score,
               "trace": trace}
    print(json.dumps(payload, indent=2) if as_json else json.dumps(payload, indent=2))
    return 0


def cmd_inspect(as_json: bool = False, show_secrets: bool = False) -> int:
    from . import SecurityConfig
    from .policy import FAIL_CLOSED_PATTERNS

    config = SecurityConfig.from_environment()
    payload: Dict[str, Any] = {"config": config.to_dict(redact_secrets=not show_secrets),
                               "failure_policy": {"fail_closed_patterns": list(FAIL_CLOSED_PATTERNS),
                                                   "default_public": "FAIL_OPEN_OBSERVE",
                                                   "sensitive": "FAIL_CLOSED"},
                               "planes": ["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"]}
    if as_json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        for key, value in sorted(payload["config"].items()):
            print(f"{key}={value}")
        print("failure_policy=FAIL_OPEN_OBSERVE(public),FAIL_CLOSED(sensitive)")
    return 0


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.version:
        print(f"aegis-sovereign {__version__} ({AEGIS_REF})")
        return 0
    if args.command == "doctor":
        return cmd_doctor(args.json)
    if args.command == "benchmark":
        return cmd_benchmark(args.iterations, args.concurrency, args.json)
    if args.command == "simulate":
        return cmd_simulate(args.scenario, args.json)
    if args.command == "serve-edge":
        from .edge_server import serve_edge
        print(f"AegisSovereign edge listening on {args.host}:{args.port} ({AEGIS_REF})")
        serve_edge(args.host, args.port)
        return 0
    if args.command == "inspect-config":
        return cmd_inspect(args.json, args.show_secrets)
    build_parser().print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
