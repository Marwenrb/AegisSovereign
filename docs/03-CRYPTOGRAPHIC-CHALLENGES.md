# 03 — Cryptographic Challenges and Proof-of-Work

**Cristi Labs** ([cristilabs.net](https://cristilabs.net)) · **Marouan Rabai**
([marwenrabai.com](https://marwenrabai.com))

## Signed integrity token

```python
from aegis_sovereign.client_challenge import SignedChallenge

service = SignedChallenge("high-entropy-secret", ttl_seconds=60)
issued = service.issue(
    session_id="session-123",
    tls_channel_id="tls-exporter-abc",
    client_ip="203.0.113.9",
    surface_scope="payout",
    claims={"scope": "payout"},
)
valid, reason = service.verify_token(
    issued.token,
    session_id="session-123",
    tls_channel_id="tls-exporter-abc",
    client_ip="203.0.113.9",
    surface_scope="payout",
    claims={"scope": "payout"},
)
```

The scope key is derived with HKDF-SHA256. The HMAC payload includes every
binding supplied above, timestamps, nonce, claims hash, and difficulty. A
nonce is atomically claimed from a bounded TTL cache; a second verification
returns `replay_detected`. A wrong channel, scope, subnet, claim, or secret
cannot produce a valid comparison.

## AegisPoW

```python
from aegis_sovereign.pow import AegisPoW

pow_engine = AegisPoW("high-entropy-secret", min_difficulty=14, max_difficulty=28)
puzzle = pow_engine.issue(risk_score=0.8, attack_pressure=0.6, subject="payout")
solution = AegisPoW.solve(puzzle)
assert pow_engine.verify(puzzle.token, solution, subject="payout")[0]
```

Puzzle metadata is stateless and HMAC-authenticated. The verifier performs
only timestamp, subject, signature, and leading-zero-bit checks. A browser can
use the generated vanilla snippet from `generate_client_sdk()`; no third-party
JavaScript package is required.

## Operational rules

- Keep the root secret outside source control and rotate it through deployment
  configuration.
- Use short TTLs for sensitive surfaces and do not disable replay protection.
- Bind the TLS exporter or a server-side channel identifier rather than a
  client-controlled header when the reverse proxy exposes it.
- Treat PoW as graduated friction, not identity proof; retain WebAuthn or an
  application-owned step-up for high-value actions.
