# AegisSovereign Architecture

**Cristi Labs** ([cristilabs.net](https://cristilabs.net)) maintains
AegisSovereign under the direction of **Marouan Rabai**
([marwenrabai.com](https://marwenrabai.com)). This document describes the
standard-library implementation shipped in `aegis_sovereign/`.

## Dataflow and fault domains

```mermaid
flowchart LR
    REQ[Request + headers + client signals] --> P1[P1 Network / ASN / prefix]
    REQ --> P2[P2 JA4 / JA4H / HTTP2 / QUIC]
    REQ --> P3[P3 HKDF HMAC / nonce / environment proof]
    REQ --> P4[P4 timing entropy / Markov transitions]
    REQ --> P5[P5 session graph / travel / velocity]
    REQ --> P6[P6 pointer / touch / keystroke kinematics]
    P1 --> P7[P7 log-odds calibrated ensemble]
    P2 --> P7
    P3 --> G{Cryptographic hard gate}
    P4 --> P7
    P5 --> P7
    P6 --> P7
    G -->|valid| P7
    G -->|invalid| BLOCK[Deterministic block on sensitive route]
    P7 --> P8[P8 observe / challenge / PoW / step-up / throttle / deception / block]
    P8 --> P9[P9 hashed telemetry + Merkle chain + OpenMetrics]
    P9 --> OUT[Verdict + explainable evidence]
```

Every plane has an independent `CircuitBreaker`. A malformed request or plane
exception is converted into an observable fallback: `FAIL_CLOSED` for
`payout`, `withdrawal`, `auth.login`, `signin`, `recovery`, and `admin.*`;
`FAIL_OPEN_OBSERVE` for public reads. The worker remains available and P9
still receives the failure record.

## Plane contracts and latency budgets

| Plane | Inputs | Output | Default budget |
|---|---|---|---:|
| P1 | IP, CIDR, ASN, country, timezone, RTT | network risk and prefix rotation | 0.15 ms |
| P2 | TLS/JA4, JA4H, HTTP/2, QUIC, client hints | transport contradiction score | 0.12 ms |
| P3 | session, TLS channel, subnet, scope, nonce, claims | HMAC integrity gate | 0.10 ms |
| P4 | inter-arrivals and surface history | entropy/dispersion/Markov score | 0.08 ms |
| P5 | identity, session, channel, locations | split/mule/travel score | 0.08 ms |
| P6 | pointer, touch, keyboard events | kinematics score | 0.08 ms |
| P7 | P1-P6 evidence | calibrated `[0,1]` probability | 0.10 ms |
| P8 | probability, route, attack pressure | graduated response plan | 0.05 ms |
| P9 | verdict and evidence | privacy telemetry and audit link | 0.08 ms |

Budgets are design targets; measure the deployed machine with
`aegis-sovereign benchmark`. `SecurityConfig.plane_timeout_ms` and circuit
state provide bounded failure behavior even when an optional adapter is slow.

## Cryptographic lifecycle

```mermaid
sequenceDiagram
    participant B as Browser / client
    participant E as Edge or middleware
    participant C as SignedChallenge
    participant W as AegisPoW
    participant A as Audit chain
    B->>E: Request with session + TLS channel
    E->>C: issue(scope, subnet, claims)
    C-->>B: AEGISINTEG token
    B->>E: Token + request evidence
    E->>C: HKDF key + constant-time HMAC verify
    C->>C: atomically claim one-time nonce
    alt risk requires compute
        E->>W: issue(risk, attack pressure)
        W-->>B: stateless signed SHA-256 puzzle
        B->>W: solution
    end
    E->>A: pseudonymised verdict + previous hash
    A-->>E: tamper-evident event hash / root
    E-->>B: uniform verdict shape or deception response
```

`SignedChallenge` derives a per-scope key using HKDF-SHA256 and binds
`session_id`, `tls_channel_id`, client subnet, surface scope, timestamps,
nonce, difficulty, and canonical claims. `hmac.compare_digest` is used for
verification. The legacy seven-field token remains accepted for compatibility;
when a non-zero difficulty is used the extended wire form is:

```text
AEGISINTEG.<session>.<iat>.<exp>.<difficulty>.<nonce>.<claims_hash>.<hmac_sig>
```

`AegisPoW` signs its challenge metadata with HMAC-SHA256 and checks leading
zero bits in a SHA-256 digest. Difficulty scales from 14 to 28 bits by risk
and attack pressure.

## Runtime and bounded state

`UnifiedRunner.assess_request` is synchronous and optimized for gateway hot
paths. `assess_request_async` uses a bounded executor, while
`assess_batch_async` uses an asyncio semaphore to preserve back-pressure.
`ShardedTTLCache`, `SlidingWindow`, and `ReplayNonceCache` cap entries and
evict expired/LRU state. `MaintenanceManager` rotates telemetry epochs,
prunes state, rotates challenge epochs, and isolates callback failures.

## Universal deployment

```mermaid
flowchart TB
    Client --> Nginx[Nginx auth_request]
    Client --> Traefik[Traefik ForwardAuth]
    Client --> Envoy[Envoy ext_authz]
    Client --> Native[ASGI / WSGI / Django middleware]
    Nginx --> Edge[aegis-sovereign serve-edge]
    Traefik --> Edge
    Envoy --> Edge
    Edge --> App[Node / Go / PHP / Rust / Ruby / Python app]
    Native --> App
```

The sidecar exposes `/decide` and JSON-RPC `/rpc`, `/healthz`, and
`/metrics`. Decision headers are `X-Aegis-Verdict`, `X-Aegis-Risk`, and
`X-Aegis-Challenge`. Native integrations lazy-import framework types only
when a Django response or framework application invokes them.

## Extension boundaries

Geo/ASN reputation is injected through `GeoIP` backends; application-specific
identity or WebAuthn assertions can be passed as claims/evidence. The core
does not fetch threat feeds, persist raw PII, or require a database. This
keeps the decision engine deterministic, portable, and auditable.
