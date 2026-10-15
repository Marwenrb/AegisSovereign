"""AegisSovereign P8 - resolvable response steps and full response plan."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True, slots=True)
class LadderStep:
    """One rung of the response ladder."""

    rung: int
    label: str
    action: str
    confidence: float = 0.0
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rung": self.rung,
            "label": self.label,
            "action": self.action,
            "confidence": self.confidence,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ResponsePlan:
    """A full graduated response, per risk score."""

    decision: str
    plan: List[LadderStep] = field(default_factory=list)
    latency_ms: List[float] = field(default_factory=list)
    pow_difficulty: int = 0
    step_up_required: bool = False
    tarpit_hold_ms: int = 0
    reason_codes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "plan": [s.to_dict() for s in self.plan],
            "latency_ms": self.latency_ms,
            "pow_difficulty": self.pow_difficulty,
            "step_up_required": self.step_up_required,
            "tarpit_hold_ms": self.tarpit_hold_ms,
            "reason_codes": self.reason_codes,
        }
