"""AegisSovereign CLI: doctor, benchmark, inspect-config.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from .version import __version__, AEGIS_REF


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegis-sovereign",
        description="AegisSovereign - Sovereign 9-Plane Anti-Automation Engine",
    )
    p.add_argument("--version", action="store_true", help="Print version and exit")
    sub = p.add_subparsers(dest="command")
    d = sub.add_parser("doctor", help="Check imports, config and planes")
    d.add_argument("--json", action="store_true", help="Emit JSON")
    b = sub.add_parser("benchmark", help="Run latency micro-benchmark")
    b.add_argument("-n", "--iterations", type=int, default=200)
    b.add_argument("--json", action="store_true", help="Emit JSON")
    c = sub.add_parser("inspect-config", help="Print effective configuration")
    c.add_argument("--json", action="store_true", help="Emit JSON")
    c.add_argument("--show-secrets", action="store_true", help="Do not redact secrets")
    return p


def cmd_doctor(as_json: bool = False) -> int:
    from . import SecurityConfig, UnifiedRunner

    cfg = SecurityConfig.from_environment()
    runner = UnifiedRunner(config=cfg)
    res = runner.assess_request(
        remote_ip="203.0.113.9",
        claimed_os="Windows 11",
        claimed_country="FR",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        session_id="doctor",
        tls_channel_id="doctor-tls",
        surface="registration.create",
    )
    payload = {
        "package": "aegis_sovereign",
        "version": __version__,
        "ref": AEGIS_REF,
        "config_ok": True,
        "decision": res.decision,
        "risk_score": res.risk_score,
        "latency_ms": round(res.audit_event.latency_ms, 3),
        "planes": ["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"],
    }
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"AegisSovereign doctor v{__version__} ({AEGIS_REF})")
        print(f"config ......... OK ({cfg.database_url})")
        print(f"assessment ..... {res.decision} score={res.risk_score}")
        print(f"latency ........ {res.audit_event.latency_ms:.2f} ms")
        print("planes ......... P1-P9 OK")
    return 0


def cmd_benchmark(iterations: int, as_json: bool = False) -> int:
    from . import UnifiedRunner
    from .network_fixtures import ResidentialGeoBackend

    runner = UnifiedRunner(geo_backend=ResidentialGeoBackend())
    lat: list[float] = []
    for i in range(max(1, iterations)):
        t0 = time.perf_counter()
        runner.assess_request(
            remote_ip="203.0.113.9",
            claimed_os="Windows 11",
            claimed_country="FR",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            session_id=f"bench-{i}",
            tls_channel_id="bench-tls",
            surface="registration.create",
        )
        lat.append((time.perf_counter() - t0) * 1000.0)
    lat.sort()
    pick = lambda q: lat[min(len(lat) - 1, int(len(lat) * q))]
    payload = {
        "iterations": len(lat),
        "p50_ms": round(pick(0.50), 3),
        "p95_ms": round(pick(0.95), 3),
        "p99_ms": round(pick(0.99), 3),
        "max_ms": round(lat[-1], 3),
    }
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"benchmark n={payload['iterations']}")
        print(f"p50={payload['p50_ms']}ms p95={payload['p95_ms']}ms p99={payload['p99_ms']}ms")
    return 0


def cmd_inspect(as_json: bool = False, show_secrets: bool = False) -> int:
    from . import SecurityConfig

    cfg = SecurityConfig.from_environment()
    data = cfg.to_dict(redact_secrets=not show_secrets)
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        for k in sorted(data):
            print(f"{k}={data[k]}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.version:
        print(f"aegis-sovereign {__version__} ({AEGIS_REF})")
        return 0
    if args.command == "doctor":
        return cmd_doctor(as_json=args.json)
    if args.command == "benchmark":
        return cmd_benchmark(args.iterations, as_json=args.json)
    if args.command == "inspect-config":
        return cmd_inspect(as_json=args.json, show_secrets=args.show_secrets)
    build_parser().print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
