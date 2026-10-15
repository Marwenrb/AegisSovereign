"""AegisSovereign synchronous and asynchronous nine-plane runtime.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .audit_event import AuditEvent
from .audit_sink import InMemorySink, Telemetry as _Telemetry
from .behavior import behaviour_score
from .client_challenge import SignedChallenge
from .client_signals import ClientSignals, CoherenceEngine, PopulationRarity, fingerprint_hash
from .config_model import SecurityConfig
from .governance import Governance
from .identity import BreachedCredentialScreen, SessionBinder
from .ladder_steps import ResponsePlan
from .maintenance import MaintenanceManager
from .network_fixtures import DatacenterGeoBackend, MockGeoBackend
from .network_intel import GeoIP, NetworkIntel, NetworkIntelligence
from .policy import Decision, RoutePolicy
from .pow import AegisPoW
from .resilience import CircuitBreaker
from .response_ladder import ResponseLadder
from .risk_engine import RiskEngine as _RiskEngine
from .state import ReplayNonceCache, ShardedTTLCache, SlidingWindow, prefix_for_ip
from .transport import (JA4Hash, ja4_from_dict, ja4h_fingerprint, quic_fingerprint,
                        transport_user_agent_consistency)


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AssessmentResult:
    """Immutable, explainable verdict returned to integrations."""

    decision: str
    risk_score: float
    audit_event: AuditEvent
    response_plan: ResponsePlan
    family_scores: Dict[str, float] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    telemetry_event_id: str = ""
    plane_status: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "risk_score": self.risk_score,
            "audit_event": self.audit_event.to_dict(),
            "response_plan": self.response_plan.to_dict(),
            "family_scores": dict(self.family_scores),
            "reasons": list(self.reasons),
            "telemetry_event_id": self.telemetry_event_id,
            "plane_status": dict(self.plane_status),
        }


class UnifiedRunner:
    """Composes nine independent planes with sync, async and batch APIs."""

    PLANE_NAMES = ("P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9")

    def __init__(self, engine: Optional[_RiskEngine] = None,
                 config: Optional[SecurityConfig] = None,
                 telemetry: Optional[_Telemetry] = None,
                 geo_backend: Optional[MockGeoBackend] = None,
                 governance: Optional[Governance] = None) -> None:
        self.config = config or SecurityConfig.from_environment()
        self.engine = engine or _RiskEngine(route_policy=RoutePolicy.for_surface("registration.create"),
                                            hard_gates_enabled=self.config.enable_hard_gates)
        self.telemetry = telemetry or _Telemetry(sink=InMemorySink(max_events=self.config.telemetry_max_events))
        self.geo_backend = geo_backend or DatacenterGeoBackend()
        self.network_intel = NetworkIntelligence(GeoIP(self.geo_backend))
        self.governance = governance or Governance()
        self.signed_challenge = SignedChallenge(
            secret_key=self.config.secret_key,
            ttl_seconds=self.config.signed_challenge_ttl_seconds,
            buffer_seconds=self.config.signed_challenge_buffer_seconds,
            replay_cache=ReplayNonceCache(max_entries=self.config.replay_cache_entries),
        )
        self.pow = AegisPoW(self.config.secret_key, min_difficulty=self.config.pow_min_difficulty,
                            max_difficulty=self.config.pow_max_difficulty)
        self.breach_screen = BreachedCredentialScreen()
        self.session_binder = SessionBinder()
        self.population = PopulationRarity(max_entries=min(self.config.telemetry_max_events, 50_000))
        self._session_windows: ShardedTTLCache[SlidingWindow[str]] = ShardedTTLCache(
            max_entries=self.config.replay_cache_entries)
        self._session_channels: ShardedTTLCache[str] = ShardedTTLCache(
            max_entries=self.config.replay_cache_entries)
        self._session_locations: ShardedTTLCache[tuple[float, float, float]] = ShardedTTLCache(
            max_entries=self.config.replay_cache_entries)
        self._breakers: Dict[str, CircuitBreaker[Any]] = {
            plane: CircuitBreaker(plane, self.config.circuit_failure_threshold,
                                  self.config.circuit_reset_seconds)
            for plane in self.PLANE_NAMES
        }
        self._executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="aegis-plane")
        self.maintenance = MaintenanceManager(interval_seconds=self.config.maintenance_interval_seconds)
        self.maintenance.add(self._maintenance_tick)

    def start_maintenance(self) -> None:
        self.maintenance.start()

    def stop_maintenance(self) -> None:
        self.maintenance.stop()
        self._executor.shutdown(wait=False, cancel_futures=True)

    def assess_request(self, *, remote_ip: str, claimed_os: str = "", claimed_country: str = "",
                       rtt_ms: float = 0.0, user_agent: str = "", platform: str = "",
                       languages: Optional[List[str]] = None, timezone: str = "",
                       screen_geometry: str = "", fonts: Optional[List[str]] = None,
                       gpu_renderers: Optional[List[str]] = None, codecs: Optional[List[str]] = None,
                       webdriver: bool = False, input_modality: str = "", password: str = "",
                       session_id: str = "", tls_channel_id: str = "",
                       surface: str = "registration.create", hard_gate_blocked: bool = False,
                       integrity_token: str = "", client_ip_subnet: str = "",
                       surface_scope: str = "", claims: Optional[Dict[str, Any]] = None,
                       inter_arrival_times: Sequence[float] = (), surface_history: Sequence[str] = (),
                       pointer_events: Sequence[Mapping[str, float]] = (),
                       touch_events: Sequence[Mapping[str, float]] = (),
                       keystroke_events: Sequence[Mapping[str, float]] = (),
                       client_hints: str = "", attack_pressure: float = 0.0,
                       latitude: float = 0.0, longitude: float = 0.0,
                       transport_ciphers: Optional[List[str]] = None,
                       transport_extensions: Optional[List[str]] = None,
                       **extra: Any) -> AssessmentResult:
        start = time.perf_counter()
        route_policy = RoutePolicy.for_surface(surface)
        statuses: Dict[str, str] = {name: "ok" for name in self.PLANE_NAMES}
        try:
            network = self._plane("P1", lambda: self.network_intel.assess(
                remote_ip, claimed_os=claimed_os, claimed_country=claimed_country, rtt_ms=rtt_ms), statuses)
            signals = ClientSignals(
                user_agent=user_agent, platform=platform, languages=list(languages or []), timezone=timezone,
                screen_geometry=screen_geometry, fonts=list(fonts or []), gpu_renderers=list(gpu_renderers or []),
                codecs=list(codecs or []), webdriver=webdriver, input_modality=input_modality,
                js_available=bool(extra.get("js_available", True)),
            )
            fingerprint = fingerprint_hash(signals)
            now = time.monotonic()
            self.population.register(fingerprint, now)
            population_score = self.population.score(fingerprint, now)
            coherence = CoherenceEngine().score(signals)

            ja4 = self._plane("P2", lambda: ja4_from_dict(
                ciphers=transport_ciphers or ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"],
                extensions=transport_extensions or ["server_name", "supported_groups", "ALPN"],
                tls_version=str(extra.get("tls_version", "TLSv1.3")), sni_present=bool(extra.get("sni_present", True)),
                alpn=list(extra.get("alpn", ["h2"])),
                signature_algorithms=list(extra.get("signature_algorithms", ["ecdsa_secp256r1_sha256"])),
                key_shares=list(extra.get("key_shares", ["x25519"])),
            ), statuses)
            transport_risk, transport_reasons = transport_user_agent_consistency(ja4, user_agent, client_hints)

            integrity_ok = True
            integrity_reason = "integrity_not_present"
            if integrity_token:
                integrity_ok, integrity_reason = self._plane("P3", lambda: self.signed_challenge.verify_token(
                    integrity_token, session_id=session_id, tls_channel_id=tls_channel_id, claims=claims,
                    client_ip_subnet=client_ip_subnet, surface_scope=surface_scope), statuses)
            client_score = self._client_score(signals, network.reputation_score, population_score)
            if not integrity_ok:
                client_score = 1.0
                hard_gate_blocked = True
            elif not integrity_token and surface in {"payout", "withdrawal", "auth.login", "admin"}:
                integrity_reason = "integrity_required"
                client_score = max(client_score, 0.35)

            timing_score, behaviour_features = self._plane("P4", lambda: behaviour_score(
                inter_arrival_times, surface_history, surface, pointer_events, touch_events, keystroke_events), statuses)
            identity_score = self._plane("P5", lambda: self._identity_score(
                network, password, session_id, tls_channel_id, latitude, longitude), statuses)
            kinematic_score = self._plane("P6", lambda: self._kinematic_score(
                signals, pointer_events, touch_events, keystroke_events), statuses)
            if kinematic_score > 0.0:
                timing_score = min(1.0, (timing_score + kinematic_score) / 2.0)
            graph_score = self._graph_score(network, surface, client_score)
            transport_score = min(1.0, max(network.reputation_score, transport_risk))
            decision = self._plane("P7", lambda: self.engine.assess(
                surface=surface, network=network, client_signals=signals, identity_score=identity_score,
                graph_score=graph_score, behaviour_score=timing_score, hard_gate_blocked=hard_gate_blocked,
                transport_score=transport_score, client_score_override=client_score,
                route_policy=route_policy,
                evidence={"integrity": integrity_reason, "coherence": coherence,
                          "behaviour": behaviour_features, "transport": transport_reasons},
            ), statuses)
            plan = self._plane("P8", lambda: ResponseLadder(
                step_up_actions=self.config.step_up_actions,
                deception_threshold=self.config.deception_confidence_threshold,
                block_hard_gates_only=self.config.block_hard_gates_only,
                pow_enabled=self.config.adaptive_pow_enabled,
            ).plan_for(decision.risk_score, decision.decision, route=surface), statuses)
            plan = replace(plan, pow_difficulty=self.pow.difficulty_for(
                decision.risk_score, float(attack_pressure)))
            return self._finish(start, network, signals, fingerprint, ja4, decision, plan,
                                surface, session_id, statuses, integrity_reason,
                                behaviour_features, transport_reasons)
        except Exception as exc:
            logger.exception("Aegis plane failure")
            return self._failure_result(start, surface, session_id, route_policy, statuses, str(exc))

    async def assess_request_async(self, **kwargs: Any) -> AssessmentResult:
        """Evaluate without blocking the caller's event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, lambda: self.assess_request(**kwargs))

    async def assess_batch_async(self, requests: Sequence[Mapping[str, Any]],
                                 concurrency: int = 16) -> List[AssessmentResult]:
        """Evaluate a batch concurrently while bounding worker fan-out."""
        semaphore = asyncio.Semaphore(max(1, int(concurrency)))

        async def one(request: Mapping[str, Any]) -> AssessmentResult:
            async with semaphore:
                return await self.assess_request_async(**dict(request))

        return list(await asyncio.gather(*(one(request) for request in requests)))

    def plane_states(self) -> Dict[str, Dict[str, Any]]:
        return {name: self._breakers[name].state().__dict__ if hasattr(self._breakers[name].state(), "__dict__")
                else {"name": self._breakers[name].state().name, "failures": self._breakers[name].state().failures,
                      "opened_at": self._breakers[name].state().opened_at, "open": self._breakers[name].state().open}
                for name in self.PLANE_NAMES}

    def _plane(self, name: str, fn: Any, statuses: Dict[str, str]) -> Any:
        def fallback(exc: Exception) -> Any:
            statuses[name] = f"degraded:{type(exc).__name__}"
            raise exc
        return self._breakers[name].call(fn, fallback)

    def _client_score(self, signals: ClientSignals, network_rep: float, pop: float) -> float:
        composite = float(CoherenceEngine().score(signals)["composite"])
        if signals.webdriver:
            return max(0.85, 1.0 - composite)
        if composite >= 0.8:
            return min(0.2, network_rep * 0.5 + pop * 0.1)
        return max(0.0, min(1.0, (1.0 - composite) * 0.65 + pop * 0.35))

    def _identity_score(self, network: NetworkIntel, password: str, session_id: str, tls: str,
                        latitude: float = 0.0, longitude: float = 0.0) -> float:
        breach = self.breach_screen.check(password) if password else None
        if breach and breach.breach_found:
            return 0.95
        if session_id:
            previous = self._session_channels.get(session_id)
            if previous and previous != tls:
                return 0.9
            self._session_channels.set(session_id, tls or "unknown", ttl_seconds=3600.0)
            self.session_binder.register_device(device_id=session_id, public_key_hash=(tls or "")[:12])
            lat = latitude if latitude else network.location.latitude
            lon = longitude if longitude else network.location.longitude
            prior_location = self._session_locations.get(session_id)
            if prior_location:
                distance_km = self._haversine_km(prior_location[0], prior_location[1], lat, lon)
                elapsed = max(1.0, time.monotonic() - prior_location[2])
                if distance_km / (elapsed / 3600.0) > 900.0:
                    self._session_locations.set(session_id, (lat, lon, time.monotonic()), ttl_seconds=3600.0)
                    return 0.95
            self._session_locations.set(session_id, (lat, lon, time.monotonic()), ttl_seconds=3600.0)
        return 0.65 if network.is_datacenter else 0.1

    @staticmethod
    def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        radius = 6371.0
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        d_phi = math.radians(lat2 - lat1)
        d_lambda = math.radians(lon2 - lon1)
        value = math.sin(d_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2
        return 2.0 * radius * math.asin(min(1.0, math.sqrt(value)))

    def _kinematic_score(self, signals: ClientSignals, pointer: Sequence[Mapping[str, float]],
                         touch: Sequence[Mapping[str, float]], keys: Sequence[Mapping[str, float]]) -> float:
        if signals.input_modality in {"keyboard", "assistive", "keyboard-only"}:
            return 0.0
        scores = []
        if pointer:
            scores.append(0.8 if all(abs(float(item.get("micro_tremor", 0.0))) < 0.01 for item in pointer) else 0.0)
        if touch:
            scores.append(0.7)
        if keys:
            scores.append(0.75)
        return sum(scores) / len(scores) if scores else 0.0

    def _graph_score(self, network: NetworkIntel, surface: str, client_score: float) -> float:
        if network.is_shared_egress and client_score > 0.5:
            return 0.75
        if surface in ("payout", "withdrawal", "recovery", "password_reset", "api.export"):
            return 0.35 if network.is_datacenter else 0.15
        return 0.55 if network.is_datacenter else 0.05

    def _finish(self, start: float, network: NetworkIntel, signals: ClientSignals, fingerprint: str,
                ja4: JA4Hash, decision: Decision, plan: ResponsePlan, surface: str,
                session_id: str, statuses: Dict[str, str], integrity_reason: str,
                behaviour_features: Dict[str, float], transport_reasons: List[str]) -> AssessmentResult:
        elapsed = (time.perf_counter() - start) * 1000.0
        reasons = list(decision.reasons)
        if integrity_reason != "integrity_not_present":
            reasons.append(integrity_reason)
        reasons.extend(transport_reasons)
        evidence = {
            "ip": network.remote_ip,
            "user_agent": signals.user_agent,
            "network": dict(network.risk_features),
            "prefix": network.prefix,
            "asn_class": network.asn_class,
            "transport_ja4": ja4.ja4_client,
            "transport_ja4h": ja4h_fingerprint("GET", surface, ("host", "user-agent")),
            "transport_quic": quic_fingerprint(),
            "client_fingerprint": fingerprint,
            "client_coherence": CoherenceEngine().score(signals),
            "behaviour": behaviour_features,
            "identity": {"webdriver": signals.webdriver},
        }
        audit = AuditEvent(actor=session_id or "anonymous", surface=surface, decision=decision.decision,
                           score=decision.risk_score, family_scores=decision.family_scores,
                           reasons=reasons, evidence=evidence, response={"plan": plan.to_dict()},
                           latency_ms=elapsed)
        audit = self._plane("P9", lambda: self.telemetry.emit(audit), statuses)
        self.governance.record_decision(decision.decision)
        return AssessmentResult(decision.decision, decision.risk_score, audit, plan,
                                decision.family_scores, reasons, audit.event_id, dict(statuses))

    def _failure_result(self, start: float, surface: str, session_id: str, policy: RoutePolicy,
                        statuses: Dict[str, str], detail: str) -> AssessmentResult:
        decision = "block" if not policy.fail_open else "allow"
        score = 0.9999 if decision == "block" else 0.25
        reason = "plane_failure_fail_closed" if decision == "block" else "plane_failure_observe"
        plan = ResponseLadder(pow_enabled=False).plan_for(score, decision, route=surface)
        audit = AuditEvent(actor=session_id or "anonymous", surface=surface, decision=decision, score=score,
                           reasons=[reason], evidence={"error": detail, "failure_mode": policy.failure_mode},
                           response={"plan": plan.to_dict()}, latency_ms=(time.perf_counter() - start) * 1000.0)
        self.telemetry.emit(audit)
        return AssessmentResult(decision, score, audit, plan, {}, [reason], audit.event_id, dict(statuses))

    def _maintenance_tick(self) -> None:
        self.signed_challenge.rotate()
        self._session_windows.prune()
        self._session_channels.prune()
        self._session_locations.prune()


class AsyncUnifiedRunner(UnifiedRunner):
    """Named async compatibility surface; sync methods remain available."""

    async def assess(self, **kwargs: Any) -> AssessmentResult:
        return await self.assess_request_async(**kwargs)
