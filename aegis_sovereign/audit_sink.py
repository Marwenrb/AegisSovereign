"""AegisSovereign — high-concurrency telemetry & audit pipeline.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import hashlib
import logging
import statistics
import threading
import time
import uuid
from collections import deque
from dataclasses import replace
from typing import Any, Deque, Dict, List, Optional

from .audit_event import AuditEvent, FAMILY_ORDER
from .audit_chain import MerkleAuditChain

logger = logging.getLogger(__name__)


class _NoOpSink:
    """Trivial sink that discards everything. The always-available default."""

    def emit(self, event: AuditEvent) -> None:
        return None

    def snapshot(self) -> Dict[str, Any]:
        return {"sink": "noop"}


def _percentile(sorted_vals: List[float], pct: float) -> Optional[float]:
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return round(sorted_vals[0], 4)
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = k - lo
    return round(sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * frac, 4)


class InMemorySink:
    """Retention-limited ring-buffer sink + percentile histograms."""

    def __init__(
        self,
        max_events: int = 50_000,
        min_score_for_stats: float = 0.5,
    ) -> None:
        self._lock = threading.RLock()
        self._events: Deque[AuditEvent] = deque(maxlen=max(1, max_events))
        self._max_events = max_events
        self._min_score_for_stats = min_score_for_stats
        self._family_decisions: Dict[str, Dict[str, int]] = {
            fam: {"allow": 0, "challenge": 0, "stepup": 0, "throttle": 0, "block": 0}
            for fam in FAMILY_ORDER
        }
        self._scores: Deque[float] = deque(maxlen=max(1, max_events))
        self._latencies: Deque[float] = deque(maxlen=max(1, max_events))

    def emit(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)
            ds = self._family_decisions
            for fam in FAMILY_ORDER:
                v = event.family_scores.get(fam)
                if v is None:
                    continue
                dec = event.decision
                if dec in ds[fam]:
                    ds[fam][dec] += 1
            if event.score >= self._min_score_for_stats:
                self._scores.append(float(event.score))
            try:
                latency = float(event.latency_ms or 0.0)
            except (TypeError, ValueError):
                latency = 0.0
            self._latencies.append(latency)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            scores = sorted(self._scores)
            lats = sorted(self._latencies)
            dims: Dict[str, Dict[str, Any]] = {}
            for fam, counts in self._family_decisions.items():
                total = sum(counts.values())
                dims[fam] = {k: v for k, v in counts.items()}
                if total:
                    dims[fam]["_pct_block"] = round(100.0 * counts["block"] / total, 2)
            s_mean = round(statistics.fmean(scores), 4) if scores else None
            l_mean = round(statistics.fmean(lats), 4) if lats else None
            return {
                "events": len(self._events),
                "family_decisions": dims,
                "score_sum": round(sum(scores), 4),
                "score_count": len(scores),
                "score_mean": s_mean,
                "score_max": round(max(scores), 4) if scores else None,
                "score_min": round(min(scores), 4) if scores else None,
                "score_p50": _percentile(scores, 50),
                "score_p95": _percentile(scores, 95),
                "score_p99": _percentile(scores, 99),
                "latency_p50_ms": _percentile(lats, 50),
                "latency_p95_ms": _percentile(lats, 95),
                "latency_p99_ms": _percentile(lats, 99),
                "latency_mean_ms": l_mean,
            }

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            for fam in self._family_decisions:
                for k in self._family_decisions[fam]:
                    self._family_decisions[fam][k] = 0
            self._scores.clear()
            self._latencies.clear()

    def openmetrics(self) -> str:
        """Return a dependency-free OpenMetrics text exposition."""
        snapshot = self.snapshot()
        lines = [
            "# HELP aegis_events_total Security decisions retained",
            "# TYPE aegis_events_total counter",
            f"aegis_events_total {snapshot['events']}",
        ]
        for family, counts in snapshot["family_decisions"].items():
            for decision in ("allow", "challenge", "stepup", "throttle", "block"):
                lines.append(f'aegis_verdicts_total{{plane="{family}",decision="{decision}"}} {counts[decision]}')
        quantiles = {"p50": "0.5", "p95": "0.95", "p99": "0.99"}
        for quantile, label in quantiles.items():
            value = snapshot.get(f"latency_{quantile}_ms")
            if value is not None:
                lines.append(f'aegis_latency_ms{{quantile="{label}"}} {value}')
                lines.append(f"aegis_latency_{quantile}_ms {value}")
        return "\n".join(lines) + "\n"


class _HashingContext:
    """Hash-based pseudonymiser so raw identifiers never touch log lines."""

    def __init__(self, salt: str | None = None):
        self._root = salt or uuid.uuid4().hex
        self._epoch = int(time.time() // 86_400)

    def rotate_if_needed(self) -> None:
        epoch = int(time.time() // 86_400)
        if epoch != self._epoch:
            self._epoch = epoch

    def hash(self, value: str, length: int = 16) -> str:
        self.rotate_if_needed()
        digest = hashlib.sha256(f"{self._root}:{self._epoch}:{value}".encode("utf-8")).hexdigest()
        return digest[:length]


class Telemetry:
    """Facade behind which audit and KPI concerns live."""

    def __init__(
        self,
        sink: Any = None,
        pseudonymise: bool = True,
        entropy_budget_bits: float = 256.0,
        logger_name: str = "aegis_sovereign",
    ) -> None:
        self._sink = sink if sink is not None else _NoOpSink()
        self._ctx = _HashingContext() if pseudonymise else None
        self._entropy = entropy_budget_bits
        self._log = logging.getLogger(logger_name)
        self.audit_chain = MerkleAuditChain()

    def emit(self, event: AuditEvent) -> AuditEvent:
        safe_evidence = event.evidence
        if self._ctx is not None:
            safe = dict(event.evidence)
            for fname in ("ip", "user_agent", "fingerprint", "token"):
                val = safe.get(fname)
                if val:
                    safe[fname] = self._ctx.hash(str(val))
            safe_evidence = safe
        chain_link = self.audit_chain.append(event.event_id, {
            "event_id": event.event_id,
            "surface": event.surface,
            "decision": event.decision,
            "score": event.score,
            "reasons": event.reasons,
        })
        enriched = replace(event, entropy_bits=self._entropy, evidence=safe_evidence,
                           previous_event_hash=chain_link.previous_hash,
                           event_hash=chain_link.event_hash)
        self._sink.emit(enriched)
        if self._log.isEnabledFor(logging.INFO):
            self._log.info(
                "AEGIS:%s|actor:%s|surface:%s|decision:%s|score:%s|reasons:%s",
                enriched.event_id, enriched.actor, enriched.surface, enriched.decision,
                enriched.score, ",".join(enriched.reasons) or "-",
            )
        return enriched

    def snapshot(self) -> Dict[str, Any]:
        return self._sink.snapshot()

    def clear(self) -> None:
        self._sink.clear()
        self.audit_chain.clear()

    def export_openmetrics(self) -> str:
        exporter = getattr(self._sink, "openmetrics", None)
        if exporter is None:
            return "# TYPE aegis_events_total counter\naegis_events_total 0\n"
        return str(exporter())

    @property
    def merkle_root(self) -> str:
        return self.audit_chain.root()
