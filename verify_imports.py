"""Module-level import check for AegisSovereign."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import aegis_sovereign as sp

print("version:", sp.__version__)
print("ref:", sp.AEGIS_REF)
assert sp.AEGIS_REF == "AEGIS-SOVEREIGN-2026"

from aegis_sovereign import (
    AegisPoW,
    AsyncUnifiedRunner,
    EdgeDecisionServer,
    MerkleAuditChain,
    ReplayNonceCache,
    UnifiedRunner,
    SecurityConfig,
    Telemetry,
    RiskEngine,
)

print("imports OK")
assert AsyncUnifiedRunner and AegisPoW and EdgeDecisionServer and MerkleAuditChain and ReplayNonceCache

cfg = SecurityConfig.from_environment(env={})
print("config database:", cfg.database_url)
assert "aegis_sovereign.db" in cfg.database_url
assert cfg.plane_timeout_ms > 0.0
assert cfg.replay_cache_entries > 0
print("all exports:", sorted([n for n in dir(sp) if not n.startswith("_")][:20]))
print("MODULE IMPORT CHECK PASSED")
