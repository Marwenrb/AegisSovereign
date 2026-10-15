"""AegisSovereign P8 - response orchestration ladder.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .ladder_steps import LadderStep, ResponsePlan

logger = logging.getLogger(__name__)

POLY_TARGET_SECONDS = 0.5
POLY_MIN_DIFFICULTY = 20
POLY_MAX_DIFFICULTY = 80
POLY_SCALE_FACTOR = 1.5

STEP_UP_ACTIONS = [
    "payout_destination_change",
    "withdrawal",
    "recovery",
    "new_device",
    "credential_change",
]


class ResponseLadder:
    """Resolves a calibrated risk score into a graduated response plan."""

    def __init__(
        self,
        *,
        step_up_actions: Optional[List[str]] = None,
        deception_threshold: float = 0.85,
        block_hard_gates_only: bool = True,
        pow_enabled: bool = True,
    ):
        self.step_up_actions = step_up_actions or list(STEP_UP_ACTIONS)
        self.deception_threshold = deception_threshold
        self.block_hard_gates_only = block_hard_gates_only
        self.pow_enabled = pow_enabled

    def plan_for(self, score: float, decided: str, *, route: str = "") -> ResponsePlan:
        plan = ResponsePlan(decision=decided)
        reason_codes: List[str] = []

        if decided == "block":
            plan.plan.append(
                LadderStep(
                    rung=6,
                    label="Block and ban",
                    action="reject_request",
                    confidence=1.0,
                    reason="hard_gate_or_confirmed_abuse",
                )
            )
            plan.reason_codes.append("block")
            return plan

        if decided == "challenge":
            plan.plan.append(
                LadderStep(
                    rung=1,
                    label="Invisible challenge",
                    action="challenge",
                    confidence=0.8,
                    reason="token_check_or_privacy_pass",
                )
            )
            plan.reason_codes.append("challenge")

        if self.pow_enabled and score > 0.5:
            difficulty = min(
                POLY_MAX_DIFFICULTY,
                max(POLY_MIN_DIFFICULTY, int(POLY_MIN_DIFFICULTY * (score * POLY_SCALE_FACTOR))),
            )
            plan.pow_difficulty = difficulty
            plan.plan.append(
                LadderStep(
                    rung=2,
                    label="Adaptive proof-of-work",
                    action="pow",
                    confidence=0.7,
                    reason=f"pow_difficulty_{difficulty}",
                )
            )
            plan.reason_codes.append("pow")

        sensitive_route = route in self.step_up_actions
        if sensitive_route and score > 0.55:
            plan.step_up_required = True
            plan.plan.append(
                LadderStep(
                    rung=3,
                    label="Step-up proof",
                    action="stepup",
                    confidence=0.9,
                    reason="step_up_on_sensitive_action",
                )
            )
            plan.reason_codes.append("stepup")

        if decided == "throttle" or (score >= 0.7 and not sensitive_route):
            hold = int(100 + score * 400)
            plan.tarpit_hold_ms = hold
            plan.plan.append(
                LadderStep(
                    rung=4,
                    label="Throttle or delay",
                    action="tarpit",
                    confidence=0.4,
                    reason=f"tarpit_hold_{hold}ms",
                )
            )
            plan.reason_codes.append("tarpit")

        if score >= self.deception_threshold and self.block_hard_gates_only:
            plan.plan.append(
                LadderStep(
                    rung=5,
                    label="Controlled deception",
                    action="deception",
                    confidence=0.95,
                    reason="controlled_deception",
                )
            )
            plan.reason_codes.append("deception")

        return plan
