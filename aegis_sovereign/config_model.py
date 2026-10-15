"""AegisSovereign immutable configuration model.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .defaults import DEFAULT_FAIL_OPEN_THRESHOLD, DEFAULT_SECRET_KEY


_DEFAULT_DB = "sqlite:///" + os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "instance", "aegis_sovereign.db")
)
_DEFAULT_GEO = os.path.join(os.path.dirname(__file__), "..", "data", "GeoLite2-Country.mmdb")
_DEFAULT_ASN = os.path.join(os.path.dirname(__file__), "..", "data", "GeoLite2-ASN.mmdb")


@dataclass(frozen=True)
class SecurityConfig:
    """Aggregates every configuration slice into one immutable object."""

    secret_key: str = field(default=DEFAULT_SECRET_KEY)
    database_url: str = field(default=_DEFAULT_DB)
    redis_url: str = field(default="redis://localhost:6379/3")
    cors_origins: str = field(default="*")
    fail_open_threshold: float = field(default=0.02)
    fail_open_for_verified: bool = field(default=False)
    edge_rule_latency_p99_ms: int = field(default=5)
    sync_decision_latency_p99_ms: int = field(default=30)
    geo_db_path: str = field(default=_DEFAULT_GEO)
    asn_db_path: str = field(default=_DEFAULT_ASN)
    enable_passive_os_fingerprint: bool = field(default=True)
    enable_rtt_consistency: bool = field(default=True)
    enable_shared_egress_detection: bool = field(default=True)
    max_subnet_tail: int = field(default=64)
    reputation_feed_urls: List[str] = field(
        default_factory=lambda: ["https://threatfeed.example.net/feeds/current.json"]
    )
    enable_ja4_tls: bool = field(default=True)
    enable_ja4_s: bool = field(default=False)
    enable_ja4_h: bool = field(default=True)
    enable_ja4_t: bool = field(default=False)
    enable_ja4_l: bool = field(default=False)
    enable_quic_fingerprint: bool = field(default=True)
    enable_hybrid_pq_key_share_check: bool = field(default=True)
    client_hint_coherence: bool = field(default=True)
    signed_challenge_ttl_seconds: int = field(default=5)
    signed_challenge_buffer_seconds: int = field(default=15)
    challenge_rotation_interval_hours: int = field(default=6)
    coherence_check_fonts: bool = field(default=True)
    coherence_check_timezone: bool = field(default=True)
    coherence_check_language: bool = field(default=True)
    coherence_check_screen_geometry: bool = field(default=True)
    coherence_check_codecs: bool = field(default=True)
    coherence_check_gpu_renderers: bool = field(default=True)
    population_rarity_window_days: int = field(default=30)
    enable_gpu_software_rasteriser_detection: bool = field(default=True)
    behaviour_enabled: bool = field(default=False)
    behaviour_sequence_model_enabled: bool = field(default=False)
    enable_passkeys: bool = field(default=True)
    enable_breach_screening: bool = field(default=True)
    enable_dpop_binding: bool = field(default=False)
    enable_session_binding: bool = field(default=True)
    recovery_cooling_off_hours: int = field(default=24)
    step_up_actions: List[str] = field(
        default_factory=lambda: [
            "payout_destination_change",
            "withdrawal",
            "recovery",
            "new_device",
            "credential_change",
        ]
    )
    biometric_enabled: bool = field(default=False)
    biometric_assurance_level: str = field(default="IAL2/AAL2")
    enable_calibrated_ensemble: bool = field(default=True)
    enable_hard_gates: bool = field(default=True)
    calibrate_shadow_mode: bool = field(default=True)
    adaptive_pow_enabled: bool = field(default=True)
    pow_difficulty_floor: int = field(default=20)
    pow_difficulty_scale_factor: float = field(default=1.5)
    privacy_pass_enabled: bool = field(default=False)
    step_up_require_human_proof: bool = field(default=True)
    tarpit_async_only: bool = field(default=True)
    deception_confidence_threshold: float = field(default=0.85)
    block_hard_gates_only: bool = field(default=True)
    rate_limit_api_create_per_minute: int = field(default=60)
    rate_limit_login_per_minute: int = field(default=10)
    rate_limit_recovery_per_hour: int = field(default=3)
    rate_limit_payout_per_hour: int = field(default=2)
    rate_limit_challenge_issue_per_minute: int = field(default=300)
    shadow_mode_capacity_ratio: float = field(default=0.25)
    drift_monitor_psi_threshold: float = field(default=0.1)
    red_team_frequency_days: int = field(default=90)
    honeypot_enabled: bool = field(default=True)
    data_minimisation_enabled: bool = field(default=True)
    biometric_special_category_consent_gathered: bool = field(default=False)
    raw_signal_retention_hours: int = field(default=24)
    derived_feature_retention_days: int = field(default=90)

    def __post_init__(self) -> None:
        if not 0.0 <= float(self.fail_open_threshold) <= 1.0:
            raise ValueError("fail_open_threshold must be in [0.0, 1.0]")
        if int(self.edge_rule_latency_p99_ms) <= 0:
            raise ValueError("edge_rule_latency_p99_ms must be positive")
        if int(self.sync_decision_latency_p99_ms) <= 0:
            raise ValueError("sync_decision_latency_p99_ms must be positive")
        if int(self.signed_challenge_ttl_seconds) <= 0:
            raise ValueError("signed_challenge_ttl_seconds must be positive")
        for fname in ("rate_limit_api_create_per_minute", "rate_limit_login_per_minute"):
            if int(getattr(self, fname)) <= 0:
                raise ValueError(f"{fname} must be positive")
        if str(self.biometric_assurance_level) not in {"IAL1/AAL1", "IAL2/AAL2"}:
            raise ValueError("biometric_assurance_level unknown")
        if not 0.0 <= float(self.deception_confidence_threshold) <= 1.0:
            raise ValueError("deception_confidence_threshold must be in [0.0, 1.0]")

    def to_dict(self, redact_secrets: bool = True) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        for fname in (
            "database_url", "redis_url", "cors_origins", "fail_open_threshold",
            "fail_open_for_verified", "edge_rule_latency_p99_ms",
        ):
            data[fname] = getattr(self, fname)
        data["secret_key"] = "***REDACTED***" if redact_secrets else self.secret_key
        for fname in (
            "sync_decision_latency_p99_ms", "geo_db_path", "asn_db_path",
            "enable_passive_os_fingerprint", "enable_rtt_consistency",
            "enable_shared_egress_detection", "max_subnet_tail",
            "reputation_feed_urls", "enable_ja4_tls", "enable_ja4_s",
            "enable_ja4_h", "enable_ja4_t", "enable_ja4_l",
        ):
            data[fname] = getattr(self, fname)
        for fname in (
            "enable_quic_fingerprint", "enable_hybrid_pq_key_share_check",
            "client_hint_coherence", "signed_challenge_ttl_seconds",
            "signed_challenge_buffer_seconds", "challenge_rotation_interval_hours",
        ):
            data[fname] = getattr(self, fname)
        for fname in (
            "coherence_check_fonts", "coherence_check_timezone",
            "coherence_check_language", "coherence_check_screen_geometry",
            "coherence_check_codecs", "coherence_check_gpu_renderers",
            "population_rarity_window_days",
            "enable_gpu_software_rasteriser_detection",
            "behaviour_enabled", "behaviour_sequence_model_enabled",
            "enable_passkeys", "enable_breach_screening", "enable_dpop_binding",
            "enable_session_binding", "recovery_cooling_off_hours",
            "step_up_actions", "biometric_enabled", "biometric_assurance_level",
        ):
            data[fname] = getattr(self, fname)
        for fname in (
            "enable_calibrated_ensemble", "enable_hard_gates",
            "calibrate_shadow_mode", "adaptive_pow_enabled",
            "pow_difficulty_floor", "pow_difficulty_scale_factor",
            "privacy_pass_enabled", "step_up_require_human_proof",
            "tarpit_async_only", "deception_confidence_threshold",
            "block_hard_gates_only", "rate_limit_api_create_per_minute",
            "rate_limit_login_per_minute", "rate_limit_recovery_per_hour",
            "rate_limit_payout_per_hour", "rate_limit_challenge_issue_per_minute",
            "shadow_mode_capacity_ratio", "drift_monitor_psi_threshold",
            "red_team_frequency_days", "honeypot_enabled",
            "data_minimisation_enabled",
            "biometric_special_category_consent_gathered",
            "raw_signal_retention_hours", "derived_feature_retention_days",
        ):
            data[fname] = getattr(self, fname)
        return data

    @classmethod
    def from_environment(cls, env=None):  # type: ignore[no-untyped-def]
        """Build a SecurityConfig from env mappings (every field wired)."""
        from .defaults import env_bool as _b
        from .defaults import env_str as _gs
        from .defaults import env_float as _f
        from .defaults import env_int as _i
        from .defaults import env_str_list as _sl

        import os as _os

        src = _os.environ if env is None else env
        base = cls()
        kw = dict(
            secret_key=_gs(src, "SECRET_KEY", base.secret_key),
            database_url=_gs(src, "DATABASE_URL", base.database_url),
            redis_url=_gs(src, "REDIS_URL", base.redis_url),
            cors_origins=_gs(src, "CORS_ORIGINS", base.cors_origins),
            fail_open_threshold=_f(src, "FAIL_OPEN_THRESHOLD", base.fail_open_threshold),
            fail_open_for_verified=_b(src, "FAIL_OPEN_FOR_VERIFIED", base.fail_open_for_verified),
            edge_rule_latency_p99_ms=_i(src, "EDGE_RULE_LATENCY_P99_MS", base.edge_rule_latency_p99_ms),
            sync_decision_latency_p99_ms=_i(src, "SYNC_DECISION_LATENCY_P99_MS", base.sync_decision_latency_p99_ms),
            geo_db_path=_gs(src, "GEO_DB_PATH", base.geo_db_path),
            asn_db_path=_gs(src, "ASN_DB_PATH", base.asn_db_path),
            enable_passive_os_fingerprint=_b(src, "ENABLE_PASSIVE_OS_FINGERPRINT", True),
            enable_rtt_consistency=_b(src, "ENABLE_RTT_CONSISTENCY", True),
            enable_shared_egress_detection=_b(src, "ENABLE_SHARED_EGRESS_DETECTION", True),
            max_subnet_tail=_i(src, "MAX_SUBNET_TAIL", base.max_subnet_tail),
            reputation_feed_urls=_sl(src, "REPUTATION_FEED_URLS", base.reputation_feed_urls),
            enable_ja4_tls=_b(src, "ENABLE_JA4_TLS", True),
            enable_ja4_s=_b(src, "ENABLE_JA4_S", False),
            enable_ja4_h=_b(src, "ENABLE_JA4_H", True),
            enable_ja4_t=_b(src, "ENABLE_JA4_T", False),
            enable_ja4_l=_b(src, "ENABLE_JA4_L", False),
            enable_quic_fingerprint=_b(src, "ENABLE_QUIC_FINGERPRINT", True),
            enable_hybrid_pq_key_share_check=_b(src, "ENABLE_HYBRID_PQ", True),
            client_hint_coherence=_b(src, "CLIENT_HINT_COHERENCE", True),
            signed_challenge_ttl_seconds=_i(src, "SIGNED_CHALLENGE_TTL", 5),
            signed_challenge_buffer_seconds=_i(src, "SIGNED_CHALLENGE_BUFFER", 15),
            challenge_rotation_interval_hours=_i(src, "CHALLENGE_ROTATION_HOURS", 6),
            coherence_check_fonts=_b(src, "COHERENCE_FONTS", True),
            coherence_check_timezone=_b(src, "COHERENCE_TZ", True),
            coherence_check_language=_b(src, "COHERENCE_LANG", True),
            coherence_check_screen_geometry=_b(src, "COHERENCE_SCREEN", True),
            coherence_check_codecs=_b(src, "COHERENCE_CODECS", True),
            coherence_check_gpu_renderers=_b(src, "COHERENCE_GPU", True),
            population_rarity_window_days=_i(src, "RARITY_WINDOW_DAYS", 30),
            enable_gpu_software_rasteriser_detection=_b(src, "ENABLE_GPU_SW", True),
            behaviour_enabled=_b(src, "BEHAVIOUR_ENABLED", False),
            behaviour_sequence_model_enabled=_b(src, "BEHAVIOUR_SEQ", False),
            enable_passkeys=_b(src, "ENABLE_PASSKEYS", True),
            enable_breach_screening=_b(src, "ENABLE_BREACH", True),
            enable_dpop_binding=_b(src, "ENABLE_DPOP", False),
            enable_session_binding=_b(src, "ENABLE_SESSION_BIND", True),
            recovery_cooling_off_hours=_i(src, "RECOVERY_COOL_HOURS", 24),
            step_up_actions=_sl(src, "STEP_UP_ACTIONS", base.step_up_actions),
            biometric_enabled=_b(src, "BIOMETRIC_ENABLED", False),
            biometric_assurance_level=_gs(src, "BIOMETRIC_LEVEL", "IAL2/AAL2"),
            enable_calibrated_ensemble=_b(src, "ENABLE_ENSEMBLE", True),
            enable_hard_gates=_b(src, "ENABLE_HARD_GATES", True),
            calibrate_shadow_mode=_b(src, "SHADOW_MODE", True),
            adaptive_pow_enabled=_b(src, "ADAPTIVE_POW", True),
            pow_difficulty_floor=_i(src, "POW_FLOOR", 20),
            pow_difficulty_scale_factor=_f(src, "POW_SCALE", 1.5),
            privacy_pass_enabled=_b(src, "PRIVACY_PASS", False),
            step_up_require_human_proof=_b(src, "STEPUP_HUMAN_PROOF", True),
            tarpit_async_only=_b(src, "TARPIT_ASYNC", True),
            deception_confidence_threshold=_f(src, "DECEPTION_THRESHOLD", 0.85),
            block_hard_gates_only=_b(src, "BLOCK_HARD_GATES_ONLY", True),
            rate_limit_api_create_per_minute=_i(src, "RL_API_CREATE", 60),
            rate_limit_login_per_minute=_i(src, "RL_LOGIN", 10),
            rate_limit_recovery_per_hour=_i(src, "RL_RECOVERY", 3),
            rate_limit_payout_per_hour=_i(src, "RL_PAYOUT", 2),
            rate_limit_challenge_issue_per_minute=_i(src, "RL_CHALLENGE", 300),
            shadow_mode_capacity_ratio=_f(src, "SHADOW_RATIO", 0.25),
            drift_monitor_psi_threshold=_f(src, "PSI_THRESHOLD", 0.1),
            red_team_frequency_days=_i(src, "RED_TEAM_DAYS", 90),
            honeypot_enabled=_b(src, "HONEYPOT", True),
            data_minimisation_enabled=_b(src, "DATA_MIN", True),
            biometric_special_category_consent_gathered=_b(src, "BIO_CONSENT", False),
            raw_signal_retention_hours=_i(src, "RAW_RETENTION_H", 24),
            derived_feature_retention_days=_i(src, "FEAT_RETENTION_D", 90),
        )
        return cls(**kw)


def config_from_dict(values: dict) -> "SecurityConfig":
    """Build a SecurityConfig from an explicit dictionary (testing)."""
    return SecurityConfig(**values)


