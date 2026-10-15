"""AegisSovereign — Sovereign-Grade 9-Plane Anti-Automation & Fraud Defense Engine.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab / Organization: Cristi Labs (https://cristilabs.net)

A sovereign-grade, defensive security architecture for detecting and
mitigating automation abuse, fraud and account takeover.

Core design principles:
    * Assume every signal will eventually be spoofed. Layer independent
      signals; weight cryptographic evidence above behavioural evidence.
    * Cryptography over inference. Where a server-verifiable proof exists,
      require it on sensitive actions.
    * Cost asymmetry. Cheap for legitimate users, expensive at scale for
      operators.
    * Risk-proportionate friction. Friction scales with the value of the
      action and the confidence of the score, never uniformly.
    * No oracle for the attacker. Uniform response shapes, randomised timing,
      and withheld reason codes deny tuning feedback.
    * Privacy and accessibility by design. Minimise data, document lawful
      basis, and never penalise assistive technology.
    * Fail deliberately. Each route has an explicit fail-open or fail-closed
      policy.

Planes
    P1 Network Intelligence     (geolocation, ASN, passive OS fingerprint,
                                RTT consistency, shared-egress)
    P2 Transport Fingerprints   (JA4 family, QUIC + HTTP/3, client-hint
                                coherence)
    P3 Client Integrity         (signed challenges, coherence engine,
                                population rarity, fingerprinting + churn)
    P4 Behaviour                (demoted to a supporting signal)
    P5 Identity & Session       (passkeys, breach screening, session binding,
                                DPoP, step-up)
    P6 Biometric Assurance      (PAD, injection detection, de-duplication)
    P7 Decision Engine          (calibrated ensemble, hard gates,
                                cost-sensitive thresholds)
    P8 Response Orchestration   (ladder: observe -> challenge -> PoW ->
                                step-up -> throttle -> deception -> block)
    P9 Governance               (drift monitoring, red teaming, incident
                                playbooks)

Normative reference: AEGIS-SOVEREIGN-2026.
"""

from __future__ import annotations

from .version import __version__, AEGIS_REF

# Public API surface (re-exported from the integration point)
from .config_model import SecurityConfig, config_from_dict
from .network_fixtures import (
    DatacenterGeoBackend,
    MockGeoBackend,
    ResidentialGeoBackend,
)
from .unified import UnifiedRunner
from .unified_runner import AsyncUnifiedRunner, AssessmentResult
from .policy import RoutePolicy, Decision
from .audit_event import AuditEvent, REASON_BITS, FAMILY_ORDER
from .audit_sink import Telemetry, InMemorySink
from .client_signals import (
    ClientSignals,
    CoherenceEngine,
    PopulationRarity,
    fingerprint_hash,
)
from .client_challenge import IntegrityToken, SignedChallenge
from .network_intel import GeoIP, NetworkIntel, NetworkIntelligence
from .fusion import CalibratedEnsemble, FamilyEvidence
from .risk_engine import RiskEngine
from .identity import BreachedCredentialScreen, SessionBinder
from .ladder_steps import LadderStep, ResponsePlan
from .response_ladder import ResponseLadder
from .governance import Governance, Incidents
from .transport import ja4_from_dict, quic_fingerprint
from .pow import AegisPoW, PoWChallenge
from .audit_chain import ChainLink, MerkleAuditChain
from .state import ReplayNonceCache, ShardedTTLCache, SlidingWindow, prefix_for_ip
from .client_sdk import ClientSDK, generate_client_sdk
from .maintenance import AsyncMaintenanceManager, MaintenanceManager
from .audit_chain import ChainLink, MerkleAuditChain
from .behavior import (
    SurfaceTransitionGraph,
    behaviour_score,
    dispersion_ratio,
    fitts_compliance,
    keystroke_risk,
    kinematics_risk,
    shannon_entropy,
    timing_risk,
    touch_risk,
)
from .client_sdk import ClientSDK, generate_client_sdk
from .maintenance import AsyncMaintenanceManager, MaintenanceManager
from .pow import AegisPoW, PoWChallenge
from .resilience import CircuitBreaker, CircuitState
from .state import (
    ReplayNonceCache,
    ShardedTTLCache,
    SlidingWindow,
    WindowSnapshot,
    prefix_for_ip,
    stable_bucket,
)

__all__ = [
    "__version__",
    "AEGIS_REF",
    "SecurityConfig",
    "config_from_dict",
    "UnifiedRunner",
    "AsyncUnifiedRunner",
    "AssessmentResult",
    "GeoIP",
    "NetworkIntel",
    "NetworkIntelligence",
    "DatacenterGeoBackend",
    "MockGeoBackend",
    "ResidentialGeoBackend",
    "ClientSignals",
    "CoherenceEngine",
    "PopulationRarity",
    "fingerprint_hash",
    "IntegrityToken",
    "SignedChallenge",
    "ja4_from_dict",
    "quic_fingerprint",
    "AegisPoW",
    "PoWChallenge",
    "ChainLink",
    "MerkleAuditChain",
    "ReplayNonceCache",
    "ShardedTTLCache",
    "SlidingWindow",
    "prefix_for_ip",
    "ClientSDK",
    "generate_client_sdk",
    "MaintenanceManager",
    "AsyncMaintenanceManager",
    "RiskEngine",
    "CalibratedEnsemble",
    "FamilyEvidence",
    "RoutePolicy",
    "Decision",
    "LadderStep",
    "ResponsePlan",
    "ResponseLadder",
    "Telemetry",
    "InMemorySink",
    "AuditEvent",
    "REASON_BITS",
    "FAMILY_ORDER",
    "Governance",
    "Incidents",
    "BreachedCredentialScreen",
    "SessionBinder",
    "ChainLink",
    "MerkleAuditChain",
    "SurfaceTransitionGraph",
    "behaviour_score",
    "dispersion_ratio",
    "fitts_compliance",
    "keystroke_risk",
    "kinematics_risk",
    "shannon_entropy",
    "timing_risk",
    "touch_risk",
    "ClientSDK",
    "generate_client_sdk",
    "AsyncMaintenanceManager",
    "MaintenanceManager",
    "AegisPoW",
    "PoWChallenge",
    "CircuitBreaker",
    "CircuitState",
    "ReplayNonceCache",
    "ShardedTTLCache",
    "SlidingWindow",
    "WindowSnapshot",
    "prefix_for_ip",
    "stable_bucket",
]
