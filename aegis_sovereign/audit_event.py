"""AegisSovereign — immutable audit-event record.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

# Human-readable reason-code strings used in audit trails. These never reach
# the client; they are for analysts and appeals only.
REASON_BITS = [
    "network_cgor",
    "network_proxy",
    "network_country_mismatch",
    "transport_ja4_block",
    "transport_quic_leak",
    "client_webdriver",
    "client_coherence",
    "client_popularity",
    "client_fingerprint_churn",
    "identity_breach",
    "identity_binding",
    "identity_stepup",
    "behaviour_session",
    "rate_limit",
    "hard_gate_rejected",
    "deny_list",
]

# Signal families, in log-odds fusion order (see :mod:`aegis_sovereign.fusion`).
FAMILY_ORDER = [
    "network",
    "transport",
    "client",
    "identity",
    "behaviour",
    "graph",
]

# Default entropy budget for evidence bundles (bits).
DEFAULT_ENTROPY_BUDGET_BITS = 256.0


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """A single, immutable audit record."""

    event_id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    actor: str = ""  # tenant id, api key prefix, or "system"
    surface: str = ""  # e.g. "registration.create", "signin", "payout"
    decision: str = ""  # allow | challenge | stepup | throttle | block
    score: float = 0.0
    family_scores: Dict[str, float] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    response: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    entropy_bits: float = 0.0
    source: str = "aegis_sovereign"
    previous_event_hash: str = ""
    event_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "ts": self.timestamp,
            "actor": self.actor,
            "surface": self.surface,
            "decision": self.decision,
            "score": self.score,
            "family_scores": self.family_scores,
            "reasons": self.reasons,
            "evidence": self.evidence,
            "response": self.response,
            "latency_ms": self.latency_ms,
            "entropy_bits": round(self.entropy_bits, 3),
            "source": self.source,
            "previous_event_hash": self.previous_event_hash,
            "event_hash": self.event_hash,
        }
