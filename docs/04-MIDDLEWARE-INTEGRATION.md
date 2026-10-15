# 04 — Middleware and Edge Integration

**Cristi Labs** ([cristilabs.net](https://cristilabs.net)) · **Marouan Rabai**
([marwenrabai.com](https://marwenrabai.com))

## Native Python adapters

```python
# ASGI: FastAPI, Starlette, Litestar, Quart
from aegis_sovereign.middleware import StarletteAegisMiddleware
app.add_middleware(StarletteAegisMiddleware)

# WSGI: Flask, Gunicorn, standard WSGI
from aegis_sovereign.middleware import WSGIAegisMiddleware
application = WSGIAegisMiddleware(application)

# Django settings.py
MIDDLEWARE = [
    "aegis_sovereign.middleware.DjangoAegisMiddleware",
    *MIDDLEWARE,
]
```

Framework imports are lazy. Applications can pass a shared `UnifiedRunner` to
all workers when they need a common configuration, or let `build_runner()`
construct one from environment variables.

## Flask guard

```python
from aegis_sovereign.middleware import flask_guard

guard = flask_guard()

@app.before_request
def protect_request():
    verdict = guard(request)
    if verdict.decision == "block":
        return {"denied": True}, 403
```

The adapter returns `X-Aegis-Verdict` and `X-Aegis-Risk` values for response
headers. Internal reason codes remain in the audit event rather than becoming
an attacker oracle.

## Universal edge sidecar

```bash
```

Endpoints:

| Path | Purpose |
|---|---|
| `GET /healthz` | liveness response |
| `GET /metrics` | OpenMetrics text |
| `POST /decide` | JSON request assessment |
| `POST /rpc` | JSON-RPC 2.0-compatible assessment |

The decision headers are `X-Aegis-Verdict`, `X-Aegis-Risk`, and
`X-Aegis-Challenge`. A gateway in Node.js, Go, PHP, Rust, or Ruby can send
the request JSON without importing Python.

For Nginx:

```nginx
location / {
    auth_request /_aegis;
    proxy_pass http://application;
}
location = /_aegis {
    internal;
    proxy_pass http://127.0.0.1:8787/decide;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Aegis-Surface $request_uri;
    proxy_set_header X-Session-Id $cookie_session;
}
```

Keep the sidecar on a private interface and expose only the gateway path.
