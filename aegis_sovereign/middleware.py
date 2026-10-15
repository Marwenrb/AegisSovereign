"""AegisSovereign web middleware (FastAPI/Starlette + Flask).

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .config_model import SecurityConfig
from .unified_runner import UnifiedRunner


@dataclass
class AegisResult:
    decision: str
    risk_score: float
    reasons: list
    family_scores: Dict[str, float]


def build_runner(config: Optional[SecurityConfig] = None) -> UnifiedRunner:
    return UnifiedRunner(config=config or SecurityConfig.from_environment(env={}))


class StarletteAegisMiddleware:
    """Starlette/FastAPI middleware enforcing AegisSovereign decisions."""

    def __init__(self, app: Any, runner: Optional[UnifiedRunner] = None) -> None:
        self.app = app
        self.runner = runner or build_runner()

    async def __call__(self, scope: Any, receive: Any, send: Any) -> Any:
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        client = scope.get("client")
        remote_ip = client[0] if client else "0.0.0.0"
        result = self.runner.assess_request(
            remote_ip=remote_ip,
            user_agent=headers.get("user-agent", ""),
            session_id=headers.get("x-session-id", ""),
            tls_channel_id=headers.get("x-tls-channel", remote_ip),
            surface=scope.get("path", "/"),
        )
        if result.decision == "block":
            await send({
                "type": "http.response.start", "status": 403,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({"type": "http.response.body", "body": b'{"denied": true}'})
            return None
        scope["state"] = {"aegis": result}
        return await self.app(scope, receive, send)


def flask_guard(runner: Optional[UnifiedRunner] = None) -> Callable:
    """Flask before-request guard returning (decision, score) or None."""

    active = runner or build_runner()

    def guard(request: Any) -> Optional[AegisResult]:
        result = active.assess_request(
            remote_ip=getattr(request, "remote_addr", "0.0.0.0") or "0.0.0.0",
            user_agent=request.headers.get("User-Agent", ""),
            session_id=request.headers.get("X-Session-Id", ""),
            tls_channel_id=request.headers.get("X-Tls-Channel", "tls"),
            surface=request.path or "/",
        )
        return AegisResult(
            decision=result.decision,
            risk_score=result.risk_score,
            reasons=result.reasons,
            family_scores=result.family_scores,
        )

    return guard
