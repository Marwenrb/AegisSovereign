# 05 — CLI Reference, Benchmarking & Production Operations

**Lead Architect & Developer:** [Marouan Rabai](https://marwenrabai.com)  
**Maintained by:** [Cristi Labs](https://cristilabs.net)  
**Normative Reference:** `AEGIS-SOVEREIGN-2026`

---

## Command-Line Interface (CLI)

The `aegis-sovereign` binary is installed automatically via `pyproject.toml`. It operates with zero runtime external dependencies and supports operations, diagnostics, benchmarking, and edge serving.

---

## 1. System Doctor (`doctor`)

Validates active configuration, database paths, cryptographic roundtrips, and plane calibration:

```bash
aegis-sovereign doctor
```

### Sample Output
```text
AegisSovereign doctor v3.1.0 (AEGIS-SOVEREIGN-2026)
attribution ... Cristi Labs / Marouan Rabai
config ........ OK (sqlite:///instance/aegis_sovereign.db)
crypto ........ OK
assessment .... challenge score=0.6690
latency ....... 0.304 ms
planes ........ P1-P9 OK
```

### Exit Codes
- `0`: All subsystems healthy and operating within latency budget.
- `1`: Validation failed (e.g. invalid database path, failed cryptographic assertion).

---

## 2. High-Concurrency Latency Benchmarking (`benchmark`)

Measures multi-threaded throughput and latency percentiles (p50, p95, p99, p99.9) on the local host:

```bash
# Run 1,000 evaluations across 8 worker threads
aegis-sovereign benchmark -n 1000 --concurrency 8
```

### Sample Output
```text
benchmark n=1000 concurrency=8 rps=3482.15
p50=0.285ms p95=0.812ms p99=1.420ms p99.9=1.890ms
```

### Production Latency Targets

| Quantile | Target Latency | Significance |
| :--- | :--- | :--- |
| **p50 (Median)** | `< 0.35 ms` | Typical overhead added to healthy user requests. |
| **p95** | `< 0.90 ms` | Tail latency under moderate concurrent load. |
| **p99** | `< 2.00 ms` | Maximum latency ceiling before circuit breakers intervene. |

---

## 3. Configuration Inspection (`inspect-config`)

Dumps the hydrated `SecurityConfig` state with all secrets and cryptographic keys redacted:

```bash
# Formatted JSON output
aegis-sovereign inspect-config --json
```

### Sample Output
```json
{
  "secret_key": "***REDACTED***",
  "database_url": "sqlite:///instance/aegis_sovereign.db",
  "fail_open_threshold": 0.02,
  "signed_challenge_ttl_seconds": 5,
  "signed_challenge_buffer_seconds": 15,
  "plane_timeout_ms": 0.75,
  "circuit_failure_threshold": 3,
  "circuit_reset_seconds": 5.0,
  "rate_limit_login_per_minute": 10,
  "rate_limit_payout_per_hour": 2
}
```

---

## 4. Universal Edge Server (`serve-edge`)

Runs the built-in HTTP server to serve decisions directly to reverse proxies or non-Python backend services:

```bash
aegis-sovereign serve-edge --host 0.0.0.0 --port 8787
```

---

## Production Operational Tuning

### Surface Sensitivity Tuning
Different endpoints represent different financial and operational risk levels. Configure surface policies in `.env`:

```ini
# Enforce strict step-up authentication on sensitive routes
STEP_UP_ACTIONS=payout_destination_change,withdrawal,recovery,new_device,credential_change

# Rate-limit thresholds (requests per window)
RL_LOGIN=10
RL_PAYOUT=2
RL_RECOVERY=3
RL_API_CREATE=60
```

### Telemetry Retention & Privacy Tuning
AegisSovereign minimizes retained privacy data and automatically pseudonyms client identifiers:

```ini
# Maximum audit events retained in sliding memory ring-buffer
TELEMETRY_MAX_EVENTS=50000

# Raw IP / UA retention (hours before eviction)
RAW_RETENTION_H=24

# Derived feature retention (days)
FEAT_RETENTION_D=90
```

---

## Operational Troubleshooting

### Issue 1: `reason="expired"` on Client Challenges
- **Cause:** Client device clock is skewed significantly relative to server time.
- **Solution:** AegisSovereign includes a configurable `buffer_seconds` parameter (default: 15s). If targeting mobile devices on unstable connections, increase `SIGNED_CHALLENGE_BUFFER=30` in `.env`.

### Issue 2: Residential Users Receiving `challenge` Verdicts
- **Cause:** Client is behind a carrier-grade NAT (CGNAT) or corporate shared egress with high subnet rotation.
- **Solution:** Verify `P1` network intelligence flags. Legitimate residential users with high coherence scores (`P3 >= 0.8`) will receive `allow` even on shared egress when `FAIL_OPEN_FOR_VERIFIED=1`.
