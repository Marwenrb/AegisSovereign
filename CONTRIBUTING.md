# Contributing — AegisSovereign

Thanks for helping harden the sovereign 9-plane engine. Maintained by
**Cristi Labs**, led by **Marouan Rabai (https://marwenrabai.com)**.

1. Fork, branch from `main` (`feat/<plane>-<change>`), keep diffs focused.
2. Run before pushing:
   `python verify_imports.py && python verify_config.py && python verify_unified.py`
   and `python -m unittest tests.test_aegis_sovereign -v`.
3. Target Python 3.10+, zero core dependencies, strict typing and
   sub-millisecond P99 assessment latency.
4. Document new env vars in `.env.example`, `README.md`, and
   `SecurityConfig.from_environment()` wiring.
5. Never commit secrets, `.db` files, or GeoIP databases.
6. Security-sensitive changes require a test proving attacker-cost asymmetry.
