"""AegisSovereign UnifiedRunner: 9-plane composition - part 1."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .client_signals import ClientSignals, CoherenceEngine, fingerprint_hash
from .client_challenge import SignedChallenge
from .config_model import SecurityConfig
from .risk_engine import RiskEngine as _RiskEngine
from .governance import Governance
from .identity import BreachedCredentialScreen, SessionBinder
from .network_fixtures import DatacenterGeoBackend, MockGeoBackend
from .network_intel import GeoIP, NetworkIntel, NetworkIntelligence
from .response_ladder import ResponseLadder
from .policy import RoutePolicy
from .audit_event import AuditEvent
from .audit_sink import Telemetry as _Telemetry
from .transport import ja4_from_dict, quic_fingerprint
from .ladder_steps import ResponsePlan

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AssessmentResult:
    decision: str
    risk_score: float
    audit_event: AuditEvent
    response_plan: ResponsePlan
    family_scores: Dict[str, float] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    telemetry_event_id: str = ""


class UnifiedRunner:
    """Composes every evidence family into one auditable decision."""

    def __init__(
        self,
        engine: Optional[_RiskEngine] = None,
        config: Optional[SecurityConfig] = None,
        telemetry: Optional[_Telemetry] = None,
        geo_backend: Optional[MockGeoBackend] = None,
        governance: Optional[Governance] = None,
    ) -> None:
        self.config = config or SecurityConfig.from_environment()
        self.engine = engine or _RiskEngine(route_policy=RoutePolicy(route="registration.create"))
        self.telemetry = telemetry or _Telemetry()
        self.geo_backend = geo_backend or DatacenterGeoBackend()
        self.governance = governance or Governance()
        self.signed_challenge = SignedChallenge(
            secret_key=self.config.secret_key,
            ttl_seconds=self.config.signed_challenge_ttl_seconds,
            buffer_seconds=self.config.signed_challenge_buffer_seconds,
        )
        self.breach_screen = BreachedCredentialScreen()
        self.session_binder = SessionBinder()

    def assess_request(
        self,
        *,
        remote_ip: str,
        claimed_os: str = "",
        claimed_country: str = "",
        rtt_ms: float = 0.0,
        user_agent: str = "",
        platform: str = "",
        languages: Optional[List[str]] = None,
        timezone: str = "",
        screen_geometry: str = "",
        fonts: Optional[List[str]] = None,
        gpu_renderers: Optional[List[str]] = None,
        codecs: Optional[List[str]] = None,
        webdriver: bool = False,
        input_modality: str = "",
        password: str = "",
        session_id: str = "",
        tls_channel_id: str = "",
        surface: str = "registration.create",
        hard_gate_blocked: bool = False,
    ) -> AssessmentResult:
        start = time.monotonic()
        geo = GeoIP(self.geo_backend)
        network = NetworkIntelligence(geo).assess(
            remote_ip, claimed_os=claimed_os,
            claimed_country=claimed_country, rtt_ms=rtt_ms,
        )
        signals = ClientSignals(
            user_agent=user_agent,
            platform=platform,
            languages=list(languages or []),
            timezone=timezone,
            screen_geometry=screen_geometry,
            fonts=fonts or [],
            gpu_renderers=gpu_renderers or [],
            codecs=codecs or [],
            webdriver=webdriver,
            input_modality=input_modality,
        )
        fingerprint = fingerprint_hash(signals)
        population_score = 0.15
        cs = self._client_score(signals, network.reputation_score, population_score)
        ids = self._identity_score(network, password, session_id, tls_channel_id)
        gs = self._graph_score(network, surface, cs)
        ja4 = ja4_from_dict(
            ciphers=["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"],
            extensions=["server_name", "supported_groups", "ALPN"],
            tls_version="TLSv1.3",
            sni_present=True,
            alpn=["h2"],
            signature_algorithms=["ecdsa_secp256r1_sha256"],
            key_shares=["x25519"],
        )
        return self._run(
            start, network, signals, fingerprint, population_score,
            cs, ids, gs, ja4, session_id, surface, hard_gate_blocked,
        )

    def _rarity_score(self, fingerprint: str, now: float) -> float:
        return 0.15

    def _client_score(self, signals: ClientSignals, net_rep: float, pop: float) -> float:
        coh = CoherenceEngine().score(signals)
        composite = float(coh["composite"])
        if signals.webdriver:
            return max(0.85, composite)
        if coh["all_checks_pass"] and composite >= 0.8:
            return min(0.2, net_rep)
        return max(0.0, min(1.0, (1.0 - composite) * 0.6 + pop * 0.4))

    def _identity_score(self, network: NetworkIntel, pw: str, sid: str, tls: str) -> float:
        breach = self.breach_screen.check(pw) if pw else None
        if breach and breach.breach_found:
            return 0.85
        if network.is_datacenter:
            return 0.65
        device = sid and self.session_binder.register_device(
            device_id=sid, public_key_hash=(tls or "")[:12]
        )
        return 0.1 if device and device.active else 0.4

    def _graph_score(self, network: NetworkIntel, surface: str, cs: float) -> float:
        if network.is_shared_egress and cs > 0.5:
            return 0.75
        if surface in ("payout", "withdrawal", "recovery"):
            return 0.35 if network.is_datacenter else 0.15
        if network.is_datacenter:
            return 0.55
        return 0.05

    def _run(
        self,
        start: float,
        network: NetworkIntel,
        signals: ClientSignals,
        fingerprint: str,
        population_score: float,
        client_score: float,
        identity_score: float,
        graph_score: float,
        ja4: Any,
        session_id: str,
        surface: str,
        hard_gate_blocked: bool,
    ) -> AssessmentResult:
        decision = self.engine.assess(
            surface=surface,
            network=network,
            client_signals=signals,
            identity_score=identity_score,
            graph_score=graph_score,
            behaviour_score=0.0,
            hard_gate_blocked=hard_gate_blocked,
        )
        ladder = ResponseLadder(
            step_up_actions=self.config.step_up_actions,
            deception_threshold=self.config.deception_confidence_threshold,
            block_hard_gates_only=self.config.block_hard_gates_only,
            pow_enabled=self.config.adaptive_pow_enabled,
        )
        plan = ladder.plan_for(decision.risk_score, decision.decision, route=surface)
        audit = AuditEvent(
            actor=session_id or "anonymous",
            surface=surface,
            decision=decision.decision,
            score=decision.risk_score,
            family_scores=decision.family_scores,
            reasons=decision.reasons,
            evidence={
                "ip": network.remote_ip,
                "user_agent": signals.user_agent,
                "network": dict(network.risk_features),
                "transport_ja4": ja4.ja4_client,
                "transport_quic": quic_fingerprint(),
                "client_fingerprint": fingerprint,
                "client_coherence": CoherenceEngine().score(signals),
                "identity": {"breach_found": False, "webdriver": signals.webdriver},
                "population_rarity": self._rarity_score(fingerprint, time.monotonic()),
            },
            response={"plan": plan.to_dict(), "ja4": ja4.ja4_client},
            latency_ms=(time.monotonic() - start) * 1000.0,
        )
        self.telemetry.emit(audit)
        self.governance.record_decision(decision.decision)
        return AssessmentResult(
            decision=decision.decision,
            risk_score=decision.risk_score,
            audit_event=audit,
            response_plan=plan,
            family_scores=decision.family_scores,
            reasons=decision.reasons,
            telemetry_event_id=audit.event_id,
        )


