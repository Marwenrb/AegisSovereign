# Changelog — AegisSovereign

## 3.0.0 — 2026-10-15 (AEGIS-SOVEREIGN-2026)

- Hard rename: `auto_register_security` → `aegis_sovereign`; `SOPHIA_REF` →
  `AEGIS_REF="AEGIS-SOVEREIGN-2026"`; `sophia.db` → `aegis_sovereign.db`;
  telemetry source/logger `aegis_sovereign`; prefix `AEGIS:` and `AEGISINTEG`.
- Fixed TLS-bound HMAC challenge format (symmetric 7-part token, true HMAC,
  canonical claims hash, constant-time compare, clock-skew buffer).
- Full `SecurityConfig.from_environment()` hydration + `__post_init__`
  validation + `to_dict(redact_secrets=True)`.
- Coherence engine rewrite (normalized weights, real font/codec, screen,
  language/timezone heuristics); thread-safe bounded `PopulationRarity`.
- `InMemorySink` → O(1) ring buffers + p50/p95/p99 score & latency snapshots;
  non-mutating telemetry pseudonymisation.
- Calibrated ensemble defaults restored (benign prior + family weights);
  corrected P1/P5/P6 risk direction; residential allow vs datacenter challenge.
- Added `cli.py` (`doctor`, `benchmark`, `inspect-config`), `__main__.py`,
  FastAPI/Flask `middleware.py`, examples, and 16-test suite.

Lead Architect & Developer: **Marouan Rabai (https://marwenrabai.com)**.
Developed & Maintained By: **Cristi Labs (https://cristilabs.net)**.
