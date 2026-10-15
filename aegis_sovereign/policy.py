"""AegisSovereign failure policy and cost-sensitive action thresholds.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)

The design principle is *risk-proportionate friction*: friction scales with
the value of the action and the confidence of the score, never uniformly.

Core idea:
    A response is triggered when the expected loss from abuse exceeds the
    expected friction cost to a legitimate user:

        P(abuse) * Loss_if_abuse  >  (1 - P(abuse)) * Friction_cost

    where:
        P(abuse)     = calibrated risk score (true probability)
        Loss_if_abuse = monetary/functional harm of a successful abuse event
        Friction_cost = annoyance + latency + false-positive cost

Policy tiers are therefore derived per-route, not global.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# --- Built-in loss estimates (USD-equivalent value of a successful abuse) ---
# These identify the route as "high value" and therefore attract friction.
ROUTE_LOSS_USD: Dict[str, float] = {
    "registration.create": 1.00,       # one fraudulent account
    "registration.bulk": 500.00,       # bulk farm
    "signin": 40.00,                   # account takeover
    "recovery": 300.00,                # account takeover via recovery
    "payout": 250.00,                  # financial abuse
    "payout_destination_change": 250.00,
    "withdrawal": 500.00,              # financial abuse
    "credential_change": 40.00,
    "new_device": 1.00,
    "api_key_rotate": 1.00,
}

FAIL_CLOSED_PATTERNS = ("payout", "auth.login", "admin.", "signin", "withdrawal", "recovery")

# Default loss when the route is unknown (a safe, moderate default).
DEFAULT_ROUTE_LOSS_USD = 5.00

# When True, events above the hard-gate threshold always block regardless of cost.
HARD_GATE_ALWAYS_BLOCKS = True

# Global floor/ceiling for calibrated risk scores (must be in [0, 1]).
MIN_VALID_SCORE = 0.0
MAX_VALID_SCORE = 1.0


def expected_loss(
    score: float,
    route: str,
    default_loss: float = DEFAULT_ROUTE_LOSS_USD,
) -> float:
    """Return the expected monetary loss of a successful abuse on *route*."""
    loss = ROUTE_LOSS_USD.get(route, default_loss)
    return score * loss


def expected_friction_loss(
    score: float,
    friction_cost_usd: float,
    default_friction: float = 0.10,
) -> float:
    """Return the expected friction cost to a legitimate user at this score."""
    return friction_cost_usd * (1.0 - score)


def cost_sensitive_threshold(
    score: float,
    route: str,
    friction_cost_usd: float = 0.10,
    default_loss: float = DEFAULT_ROUTE_LOSS_USD,
) -> bool:
    """Return True when intervention is justified on expected-loss grounds."""
    el = expected_loss(score, route, default_loss)
    ef = expected_friction_loss(score, friction_cost_usd)
    return el > ef


@dataclass(slots=True)
class RoutePolicy:
    """Per-route policy: loss, friction cost, thresholds, and fail mode."""

    route: str
    loss_usd: float = field(default_factory=lambda: DEFAULT_ROUTE_LOSS_USD)
    friction_cost_usd: float = field(default=0.10)
    friction_cost_max: float = field(default=5.00)  # cap to protect reputation
    base_threshold: float = field(default=0.50)  # sit over which intervene
    fail_open: bool = field(default=False)  # fail-closed by default
    enable_adaptive_pow: bool = field(default=True)
    enable_step_up: bool = field(default=True)
    enable_deception: bool = field(default=False)

    @staticmethod
    def for_surface(route: str) -> "RoutePolicy":
        """Return the deterministic default policy for an arbitrary surface."""
        closed = any(route == pattern or route.startswith(pattern) for pattern in FAIL_CLOSED_PATTERNS)
        return RoutePolicy(route=route, loss_usd=ROUTE_LOSS_USD.get(route, DEFAULT_ROUTE_LOSS_USD),
                           fail_open=not closed)

    @property
    def failure_mode(self) -> str:
        return "FAIL_OPEN_OBSERVE" if self.fail_open else "FAIL_CLOSED"

    def intervention_threshold(self, score: float) -> bool:
        """True when the expected-loss rule says intervene on this route."""
        return cost_sensitive_threshold(
            score, self.route, self.friction_cost_usd, self.loss_usd
        )

    def resolve(self, score: float, hard_gates_blocked: bool) -> str:
        """Map a calibrated score to a response decision string."""
        if hard_gates_blocked:
            return "block"
        if score <= self.base_threshold:
            return "allow"
        if self.intervention_threshold(score):
            return "challenge"
        # Below threshold but above base: mild friction
        if score >= self.base_threshold * 0.9:
            return "challenge"
        return "allow"


@dataclass(frozen=True, slots=True)
class Decision:
    """The full, machine-readable decision for one event."""

    decision: str  # allow | challenge | stepup | throttle | block
    risk_score: float
    route: str
    reasons: List[str] = field(default_factory=list)
    family_scores: Dict[str, float] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    response: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    cost_assessment: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "risk_score": self.risk_score,
            "route": self.route,
            "reasons": self.reasons,
            "family_scores": self.family_scores,
            "evidence": self.evidence,
            "response": self.response,
            "latency_ms": self.latency_ms,
            "cost_assessment": self.cost_assessment,
        }
