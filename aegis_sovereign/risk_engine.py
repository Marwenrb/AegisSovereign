"""Risk engine: the main orchestrator for the decision engine (P7 - AegisSovereign).

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .client_signals import ClientSignals, CoherenceEngine
from .network_intel import NetworkIntel
from .policy import Decision, RoutePolicy
from .fusion import CalibratedEnsemble

logger = logging.getLogger(__name__)


class RiskEngine:
    """Main orchestrator: fuses evidence into a calibrated Decision."""

    def __init__(
        self,
        *,
        ensemble: Optional[CalibratedEnsemble] = None,
        route_policy: Optional[RoutePolicy] = None,
        hard_gates_enabled: bool = True,
    ):
        self.ensemble = ensemble or CalibratedEnsemble()
        self.route_policy = route_policy or RoutePolicy(route="")
        self.hard_gates_enabled = hard_gates_enabled

    def assess(
        self,
        *,
        surface: str,
        network: Optional[NetworkIntel] = None,
        client_signals: Optional[ClientSignals] = None,
        identity_score: float = 0.0,
        graph_score: float = 0.0,
        behaviour_score: float = 0.0,
        hard_gate_blocked: bool = False,
    ) -> Decision:
        network = network or NetworkIntel(remote_ip="")
        client_signals = client_signals or ClientSignals()

        net_score = network.reputation_score
        transport_score = net_score
        client_score = self._client_score(client_signals)

        identity_score = max(0.0, min(1.0, identity_score))
        behaviour_score = max(0.0, min(1.0, behaviour_score))
        graph_score = max(0.0, min(1.0, graph_score))

        if hard_gate_blocked and self.hard_gates_enabled:
            decision = "block"
            score = 0.9999
            reasons = RiskEngine._reasons(network, client_signals, score, decision)
            return Decision(
                decision=decision,
                risk_score=round(score, 4),
                route=surface,
                reasons=reasons,
                family_scores={
                    "network": net_score,
                    "transport": transport_score,
                    "client": client_score,
                    "identity": identity_score,
                    "behaviour": behaviour_score,
                    "graph": graph_score,
                },
                evidence={},
                latency_ms=0.0,
                cost_assessment={"expected_loss": score * self.route_policy.loss_usd},
            )

        fused, lens, _ = self.ensemble.fuse(
            self.ensemble.make_family("network", net_score),
            self.ensemble.make_family("transport", transport_score),
            self.ensemble.make_family("client", client_score),
            self.ensemble.make_family("identity", identity_score),
            self.ensemble.make_family("behaviour", behaviour_score),
            self.ensemble.make_family("graph", graph_score),
            route=surface,
        )
        score = fused
        decision = self._route_decision(score)
        reasons = RiskEngine._reasons(network, client_signals, score, decision)
        return Decision(
            decision=decision,
            risk_score=round(score, 4),
            route=surface,
            reasons=reasons,
            family_scores={e.family: e.score for e in lens},
            evidence={},
            latency_ms=0.0,
            cost_assessment={"expected_loss": score * self.route_policy.loss_usd},
        )

    def _client_score(self, signals: Optional[ClientSignals]) -> float:
        if not signals:
            return 0.5
        coh = CoherenceEngine().score(signals)
        composite = float(coh["composite"])
        if signals.webdriver:
            return max(0.85, composite)
        if coh["all_checks_pass"] and composite >= 0.7:
            return 0.15
        return max(0.0, min(1.0, 1.0 - composite))

    def _route_decision(self, score: float) -> str:
        policy = self.route_policy
        if score >= 0.85:
            return "block"
        if score >= 0.30:
            return "challenge"
        if score <= policy.base_threshold:
            return "allow"
        if policy.intervention_threshold(score):
            return "challenge"
        if score >= policy.base_threshold * 0.9:
            return "challenge"
        return "allow"

    @staticmethod
    def _reasons(
        network: NetworkIntel,
        client_signals: ClientSignals,
        score: float,
        decision: str,
    ) -> List[str]:
        reasons: List[str] = []
        if network.is_datacenter:
            reasons.append("network_datacenter")
        if network.is_shared_egress:
            reasons.append("network_shared_egress")
        if client_signals and client_signals.webdriver:
            reasons.append("client_webdriver")
        if score >= 0.9:
            reasons.append("high_confidence_abuse")
        elif score < 0.3:
            reasons.append("low_confidence")
        return reasons
