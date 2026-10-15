"""Universal zero-dependency HTTP JSON-RPC edge decision sidecar.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Mapping, Optional, Tuple, Type

from .config_model import SecurityConfig
from .unified_runner import UnifiedRunner


def _request_kwargs(payload: Mapping[str, Any], headers: Mapping[str, str], client_ip: str) -> Dict[str, Any]:
    values = dict(payload)
    values.setdefault("remote_ip", client_ip)
    values.setdefault("user_agent", headers.get("user-agent", ""))
    values.setdefault("session_id", headers.get("x-session-id", ""))
    values.setdefault("tls_channel_id", headers.get("x-tls-channel", client_ip))
    values.setdefault("integrity_token", headers.get("x-aegis-integrity", ""))
    values.setdefault("surface", headers.get("x-aegis-surface", "/"))
    return values


class EdgeDecisionHandler(BaseHTTPRequestHandler):
    """HTTP handler compatible with Nginx auth_request and ForwardAuth."""

    runner: UnifiedRunner

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._write(HTTPStatus.OK, {"ok": True, "service": "aegis-sovereign"})
            return
        if self.path == "/metrics":
            body = self.runner.telemetry.export_openmetrics().encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._write(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path not in ("/decide", "/rpc"):
            self._write(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        try:
            length = min(1_048_576, int(self.headers.get("Content-Length", "0")))
            raw = self.rfile.read(length) if length else b"{}"
            envelope = json.loads(raw.decode("utf-8"))
            params = envelope.get("params", envelope) if isinstance(envelope, dict) else {}
            result = self.runner.assess_request(**_request_kwargs(params, self.headers, self.client_address[0]))
            payload = result.to_dict()
            if isinstance(envelope, dict) and "id" in envelope:
                payload = {"jsonrpc": "2.0", "id": envelope["id"], "result": payload}
            status = HTTPStatus.FORBIDDEN if result.decision == "block" else HTTPStatus.OK
            self._write(status, payload, result.decision, result.risk_score)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._write(HTTPStatus.BAD_REQUEST, {"error": "invalid_request", "detail": str(exc)})
        except Exception:
            self._write(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "decision_failure"})

    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _write(self, status: HTTPStatus, payload: Dict[str, Any], decision: str = "",
               risk: float = 0.0) -> None:
        body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if decision:
            self.send_header("X-Aegis-Verdict", decision)
            self.send_header("X-Aegis-Risk", f"{risk:.4f}")
            if decision == "challenge":
                self.send_header("X-Aegis-Challenge", "required")
        self.end_headers()
        self.wfile.write(body)


class EdgeDecisionServer(ThreadingHTTPServer):
    """Thread-per-request standard-library edge server."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], runner: Optional[UnifiedRunner] = None) -> None:
        active = runner or UnifiedRunner(config=SecurityConfig.from_environment(env={}))
        handler = type("AegisEdgeHandler", (EdgeDecisionHandler,), {"runner": active})
        super().__init__(address, handler)
        self.runner = active


def serve_edge(host: str = "127.0.0.1", port: int = 8787,
               runner: Optional[UnifiedRunner] = None) -> None:
    """Serve decisions until interrupted."""
    server = EdgeDecisionServer((host, int(port)), runner)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()


__all__ = ["EdgeDecisionHandler", "EdgeDecisionServer", "serve_edge"]
