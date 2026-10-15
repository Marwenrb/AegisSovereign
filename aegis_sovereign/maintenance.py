"""Non-blocking maintenance loop for bounded state and key rotation."""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Callable, Iterable, List, Optional


class MaintenanceManager:
    """Daemon maintenance runner; callbacks are short and exception-isolated."""

    def __init__(self, callbacks: Iterable[Callable[[], None]] = (), interval_seconds: float = 30.0) -> None:
        self.callbacks: List[Callable[[], None]] = list(callbacks)
        self.interval_seconds = max(0.1, float(interval_seconds))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def add(self, callback: Callable[[], None]) -> None:
        self.callbacks.append(callback)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="aegis-maintenance", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 1.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(max(0.0, float(timeout)))
            self._thread = None

    def run_once(self) -> None:
        for callback in tuple(self.callbacks):
            try:
                callback()
            except Exception:
                continue

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.run_once()


class AsyncMaintenanceManager:
    """Coroutine equivalent used by async gateway applications."""

    def __init__(self, callbacks: Iterable[Callable[[], None]] = (), interval_seconds: float = 30.0) -> None:
        self.callbacks = list(callbacks)
        self.interval_seconds = max(0.1, float(interval_seconds))
        self._stop = False

    async def run(self) -> None:
        self._stop = False
        while not self._stop:
            await asyncio.sleep(self.interval_seconds)
            for callback in tuple(self.callbacks):
                try:
                    callback()
                except Exception:
                    continue

    def stop(self) -> None:
        self._stop = True
