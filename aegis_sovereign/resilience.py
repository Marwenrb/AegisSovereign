"""Circuit breakers and deterministic plane failure handling.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Generic, Optional, TypeVar


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class CircuitState:
    name: str
    failures: int
    opened_at: float
    open: bool


class CircuitBreaker(Generic[T]):
    """Small per-plane breaker with closed/open/half-open transitions."""

    def __init__(self, name: str, failure_threshold: int = 3, reset_seconds: float = 5.0) -> None:
        self.name = name
        self.failure_threshold = max(1, int(failure_threshold))
        self.reset_seconds = max(0.01, float(reset_seconds))
        self._failures = 0
        self._opened_at = 0.0
        self._probe = False
        self._lock = threading.RLock()

    def state(self, now: Optional[float] = None) -> CircuitState:
        current = time.monotonic() if now is None else float(now)
        with self._lock:
            opened = self._opened_at > 0 and current - self._opened_at < self.reset_seconds
            return CircuitState(self.name, self._failures, self._opened_at, opened)

    def call(self, fn: Callable[[], T], fallback: Callable[[Exception], T]) -> T:
        current = time.monotonic()
        with self._lock:
            if self._opened_at:
                if current - self._opened_at < self.reset_seconds:
                    return fallback(RuntimeError(f"circuit_open:{self.name}"))
                if self._probe:
                    return fallback(RuntimeError(f"circuit_probe_busy:{self.name}"))
                self._probe = True
        try:
            result = fn()
        except Exception as exc:
            self.record_failure()
            return fallback(exc)
        else:
            self.record_success()
            return result
        finally:
            with self._lock:
                self._probe = False

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._opened_at = time.monotonic()

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = 0.0

    def reset(self) -> None:
        self.record_success()
