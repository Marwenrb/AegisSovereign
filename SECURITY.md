# AegisSovereign Security Policy

Maintained by **Cristi Labs** ([cristilabs.net](https://cristilabs.net)) and
architected by **Marouan Rabai** ([marwenrabai.com](https://marwenrabai.com)).
The normative reference is `AEGIS-SOVEREIGN-2026`.

## Security model

AegisSovereign is a defensive decision engine. It assumes that headers,
browser signals, timing, and network metadata can be forged. Independent
planes therefore provide supporting evidence, while a failed cryptographic
proof is a deterministic gate on declared sensitive routes. Public routes
default to observation on infrastructure failure so an unavailable detector
does not become an application-wide outage.

The expected-loss policy is:

```text
P(abuse) * Loss_if_abuse > Friction_cost
```

Scores are bounded calibrated probabilities, not identity assertions. Teams
must validate thresholds against their own false-positive and accessibility
requirements before enabling block actions.

## Cryptography

- `SignedChallenge` uses HKDF-SHA256-derived per-scope keys and HMAC-SHA256.
- Verification uses constant-time comparison, timestamp skew tolerance, and a
  bounded one-time nonce cache.
- `AegisPoW` uses stateless HMAC-signed metadata and SHA-256 leading-zero-bit
  work verification.
- P9 links every emitted decision to a tamper-evident hash chain and exposes
  the current Merkle-style root for independent archival.
- Telemetry hashes IPs, session identifiers, fingerprints, user agents, and
  tokens with a rotating daily epoch salt; raw evidence is kept only in the
  bounded in-memory sink configured by the operator.

## Privacy and accessibility

Do not pass raw secrets or passwords into audit evidence. Passwords are only
used by the breach-screening feature and are never returned in a verdict.
Keyboard-only and assistive-technology modalities are explicitly exempted
from pointer-kinematics penalties. Biometric signals must be opt-in with a
lawful basis and documented retention policy.

## Deployment hardening

1. Replace the development `SECRET_KEY` with a high-entropy secret from a
   secret manager; do not commit `.env` files.
2. Put the edge daemon on a private network and allow only the reverse proxy
   or application gateway to reach `/decide`.
3. Use route-specific policies. Keep `payout`, `auth.login`, recovery, and
   admin routes fail-closed; keep low-value public reads fail-open/observe.
4. Export OpenMetrics to an authenticated monitoring path and archive Merkle
   roots outside the process for forensic continuity.
5. Run `make test`, the verification scripts, and a representative benchmark
   after each configuration or adapter change.

## Reporting a vulnerability

Report vulnerabilities privately to **security@cristilabs.net**. Include the
affected version, a minimal reproduction, impact, and suggested mitigation.
We acknowledge reports within two business days and target fixes by severity:

| Severity | Target |
|---|---:|
| Critical | 7 days |
| High | 30 days |
| Medium/Low | 90 days |

Do not run automated scanners against production systems without written
scope. Red-team validation belongs in local tests, examples, and authorized
quarterly exercises. We follow coordinated disclosure and credit reporters in
`CHANGELOG.md`.
