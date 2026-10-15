"""AegisSovereign unified entry point: one auditable assessment per request.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)

Usage (Flask / any WSGI middleware)::

    from aegis_sovereign import UnifiedRunner, SecurityConfig, Telemetry
    from aegis_sovereign.policy import RoutePolicy

    config = SecurityConfig.from_environment()
    telemetry = Telemetry()
    engine = RiskEngine(route_policy=RoutePolicy(route="registration.create"))
    runner = UnifiedRunner(engine, config, telemetry)

    result = runner.assess_request(
        remote_ip="203.0.113.9",
        claimed_os="Windows 11",
        claimed_country="FR",
        user_agent="Mozilla/5.0 ...",
        session_id="sess_abc",
        tls_channel_id="tls_123",
        surface="registration.create",
    )
"""

from __future__ import annotations

import logging

from .config_model import SecurityConfig
from .network_fixtures import DatacenterGeoBackend, MockGeoBackend, ResidentialGeoBackend
from .audit_event import AuditEvent
from .audit_sink import Telemetry
from .fusion import CalibratedEnsemble
from .risk_engine import RiskEngine
from .unified_runner import UnifiedRunner

logger = logging.getLogger(__name__)

__all__ = [
    "UnifiedRunner",
    "SecurityConfig",
    "Telemetry",
    "AuditEvent",
    "MockGeoBackend",
    "DatacenterGeoBackend",
    "ResidentialGeoBackend",
]
