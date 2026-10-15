"""Lazy-imported ASGI, WSGI, Flask and Django integrations.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .config_model import SecurityConfig
from .unified_runner import UnifiedRunner


@dataclass(frozen=True, slots=True)
class AegisResult:
    decision: str
    risk_score: float
    reasons: List[str]
    family_scores: Dict[str, float]
    response_headers: Dict[str, str]


def build_runner(config: Optional[SecurityConfig] = None) -> UnifiedRunner:
    return UnifiedRunner(config=config or SecurityConfig.from_environment(env={}))


def _result(raw: Any) -> AegisResult:
    return AegisResult(
        decision=raw.decision,
        risk_score=raw.risk_score,
        reasons=list(raw.reasons),
        family_scores=dict(raw.family_scores),
        response_headers={
            "X-Aegis-Verdict": raw.decision,
            "X-Aegis-Risk": f"{raw.risk_score:.4f}",
            "X-Aegis-Challenge": raw.response_plan.response_plan_id if hasattr(raw.response_plan, "response_plan_id") else "",
        },
    )


def _runner_kwargs(remote_ip: str, headers: Dict[str, str], surface: str) -> Dict[str, Any]:
    return {
        "remote_ip": remote_ip,
        "user_agent": headers.get("user-agent", ""),
        "session_id": headers.get("x-session-id", ""),
        "tls_channel_id": headers.get("x-tls-channel", remote_ip),
        "integrity_token": headers.get("x-aegis-integrity", ""),
        "surface": surface,
    }


class StarletteAegisMiddleware:
    """ASGI middleware for FastAPI, Starlette, Litestar and Quart."""

    def __init__(self, app: Any, runner: Optional[UnifiedRunner] = None) -> None:
        self.app = app
        self.runner = runner or build_runner()

    async def __call__(self, scope: Any, receive: Any, send: Any) -> Any:
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        client = scope.get("client")
        remote_ip = client[0] if client else "0.0.0.0"
        raw = await self.runner.assess_request_async(**_runner_kwargs(remote_ip, headers, scope.get("path", "/")))
        result = _result(raw)
        if result.decision == "block":
            response_headers = [(b"content-type", b"application/json")]
            response_headers.extend((key.encode("ascii"), value.encode("latin1"))
                                    for key, value in result.response_headers.items() if value)
            await send({"type": "http.response.start", "status": 403, "headers": response_headers})
            await send({"type": "http.response.body", "body": b'{"denied":true}'})
            return None
        scope.setdefault("state", {})["aegis"] = result

        async def send_with_headers(message: Dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + [
                    (key.encode("ascii"), value.encode("latin1"))
                    for key, value in result.response_headers.items() if value
                ]
            await send(message)

        return await self.app(scope, receive, send_with_headers)


class WSGIAegisMiddleware:
    """Zero-dependency WSGI wrapper for Flask, Gunicorn and WSGI servers."""

    def __init__(self, app: Callable[..., Any], runner: Optional[UnifiedRunner] = None) -> None:
        self.app = app
        self.runner = runner or build_runner()

    def __call__(self, environ: Dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        headers = {
            "user-agent": str(environ.get("HTTP_USER_AGENT", "")),
            "x-session-id": str(environ.get("HTTP_X_SESSION_ID", "")),
            "x-tls-channel": str(environ.get("HTTP_X_TLS_CHANNEL", "")),
            "x-aegis-integrity": str(environ.get("HTTP_X_AEGIS_INTEGRITY", "")),
        }
        remote = str(environ.get("REMOTE_ADDR", "0.0.0.0"))
        raw = self.runner.assess_request(**_runner_kwargs(remote, headers, str(environ.get("PATH_INFO", "/"))))
        result = _result(raw)
        if result.decision == "block":
            body = json.dumps({"denied": True}).encode("utf-8")
            start_response("403 Forbidden", [("Content-Type", "application/json"),
                                               ("Content-Length", str(len(body)))])
            return [body]
        def wrapped_start(status: str, response_headers: List[Tuple[str, str]], exc_info: Any = None) -> Any:
            response_headers = list(response_headers) + list(result.response_headers.items())
            return start_response(status, response_headers, exc_info) if exc_info is not None else start_response(status, response_headers)
        return self.app(environ, wrapped_start)


class DjangoAegisMiddleware:
    """Django middleware without importing Django until an application uses it."""

    def __init__(self, get_response: Callable[..., Any], runner: Optional[UnifiedRunner] = None) -> None:
        self.get_response = get_response
        self.runner = runner or build_runner()

    def __call__(self, request: Any) -> Any:
        headers = {str(k).lower(): str(v) for k, v in request.headers.items()}
        raw = self.runner.assess_request(**_runner_kwargs(
            str(getattr(request, "META", {}).get("REMOTE_ADDR", "0.0.0.0")),
            headers, str(getattr(request, "path", "/")),
        ))
        result = _result(raw)
        if result.decision == "block":
            try:
                from django.http import JsonResponse  # type: ignore[import-not-found]
                return JsonResponse({"denied": True}, status=403, headers=result.response_headers)
            except ImportError:
                return {"denied": True, "status": 403, "headers": result.response_headers}
        response = self.get_response(request)
        for key, value in result.response_headers.items():
            if hasattr(response, "__setitem__") and value:
                response[key] = value
        return response


def flask_guard(runner: Optional[UnifiedRunner] = None) -> Callable[[Any], AegisResult]:
    """Return a Flask ``before_request`` guard callable."""
    active = runner or build_runner()

    def guard(request: Any) -> AegisResult:
        headers = {str(k).lower(): str(v) for k, v in request.headers.items()}
        raw = active.assess_request(**_runner_kwargs(
            str(getattr(request, "remote_addr", "0.0.0.0") or "0.0.0.0"),
            headers, str(getattr(request, "path", "/") or "/"),
        ))
        return _result(raw)

    return guard
