"""AegisSovereign CLI demo harness for the 9-plane defence system.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)

Run::

    python -m aegis_sovereign doctor
    python -m aegis_sovereign.examples.demo --sim benign
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

logger = logging.getLogger("aegis_sovereign.demo")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from aegis_sovereign.network_fixtures import DatacenterGeoBackend, ResidentialGeoBackend
from aegis_sovereign.unified_runner import UnifiedRunner
from aegis_sovereign.config_model import SecurityConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AegisSovereign - Sovereign 9-Plane Defence Demo"
    )
    parser.add_argument(
        "--sim",
        choices=["benign", "datacenter", "vpn", "proxy"],
        default="benign",
        help="Simulation mode",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level, logging.INFO))

    config = SecurityConfig.from_environment(env={})
    backend = ResidentialGeoBackend() if args.sim == "benign" else DatacenterGeoBackend()
    runner = UnifiedRunner(config=config, geo_backend=backend)

    profiles = {
        "benign": {
            "remote_ip": "203.0.113.9",
            "claimed_os": "Windows 11",
            "claimed_country": "BR",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "platform": "windows",
            "languages": ["pt-BR"],
            "timezone": "America/Sao_Paulo",
            "screen_geometry": "1920x1080x24",
            "fonts": ["Arial"],
            "gpu_renderers": ["ANGLE (NVIDIA)"],
            "codecs": ["h264"],
            "input_modality": "mouse",
        },
        "datacenter": {
            "remote_ip": "198.51.100.23",
            "claimed_os": "Windows 11",
            "claimed_country": "US",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120 Safari/537.36",
            "platform": "windows",
            "webdriver": True,
        },
        "vpn": {
            "remote_ip": "198.51.100.54",
            "claimed_os": "macOS 14",
            "claimed_country": "GB",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "platform": "macintosh",
        },
        "proxy": {
            "remote_ip": "192.0.2.77",
            "claimed_os": "Windows 10",
            "claimed_country": "DE",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "platform": "windows",
        },
    }

    profile = profiles[args.sim]
    result = runner.assess_request(
        **profile,
        session_id="demo_session",
        tls_channel_id="demo_tls",
        surface="registration.create",
    )

    print("=" * 60)
    print("AegisSovereign Defence Assessment")
    print("=" * 60)
    print(f"Simulated mode : {args.sim}")
    print(f"Remote IP      : {profile['remote_ip']}")
    print(f"Claimed OS     : {profile['claimed_os']}")
    print("-" * 60)
    print(f"Decision       : {result.decision}")
    print(f"Risk score     : {result.risk_score:.3f}")
    print(f"Family scores  : {result.family_scores}")
    print(f"Reasons        : {result.reasons}")
    print(f"Latency        : {result.audit_event.latency_ms:.2f} ms")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
