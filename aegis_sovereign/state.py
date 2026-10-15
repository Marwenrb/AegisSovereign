"""Bounded, standard-library state primitives used by the hot path.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)

The structures in this module deliberately use bounded deques and sharded
locks.  They are suitable for request-local telemetry, replay protection and
rate limiting without allowing an attacker to grow process memory forever.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Generic, Hashable, Iterator, List, Optional, Tuple, TypeVar


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class WindowSnapshot:
    """Immutable view of a sliding-window counter."""

    count: int
    first_at: float
    last_at: float
    mean_interval: float


class SlidingWindow(Generic[T]):
    """A bounded timestamp ring buffer with O(1) append and pruning."""

    def __init__(self, window_seconds: float = 60.0, max_events: int = 256) -> None:
        self.window_seconds = max(0.001, float(window_seconds))
        self.max_events = max(2, int(max_events))
        self._events: Deque[Tuple[float, T]] = deque(maxlen=self.max_events)
        self._lock = threading.RLock()

    def add(self, value: T, now: Optional[float] = None) -> None:
        current = time.monotonic() if now is None else float(now)
        with self._lock:
            self._prune_locked(current)
            self._events.append((current, value))

    def snapshot(self, now: Optional[float] = None) -> WindowSnapshot:
        current = time.monotonic() if now is None else float(now)
        with self._lock:
            self._prune_locked(current)
            timestamps = [stamp for stamp, _ in self._events]
        if len(timestamps) < 2:
            return WindowSnapshot(len(timestamps), timestamps[0] if timestamps else 0.0,
                                  timestamps[-1] if timestamps else 0.0, 0.0)
        elapsed = timestamps[-1] - timestamps[0]
        return WindowSnapshot(len(timestamps), timestamps[0], timestamps[-1],
                              elapsed / (len(timestamps) - 1))

    def values(self, now: Optional[float] = None) -> List[T]:
        current = time.monotonic() if now is None else float(now)
        with self._lock:
            self._prune_locked(current)
            return [value for _, value in self._events]

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()


class ShardedTTLCache(Generic[T]):
    """A fixed-size sharded TTL + LRU cache.

    Each shard has its own lock, so unrelated identifiers do not contend on a
    global mutex.  Eviction is deterministic: expired entries first, then the
    least recently used entries until the shard cap is respected.
    """

    def __init__(self, max_entries: int = 50_000, shards: int = 16) -> None:
        self.max_entries = max(1, int(max_entries))
        self.shards = max(1, int(shards))
        per_shard = max(1, self.max_entries // self.shards)
        self._caps = [per_shard] * self.shards
        self._caps[-1] += self.max_entries - sum(self._caps)
        self._data: List[OrderedDict[Hashable, Tuple[float, T]]] = [
            OrderedDict() for _ in range(self.shards)
        ]
        self._locks = [threading.RLock() for _ in range(self.shards)]

    def _index(self, key: Hashable) -> int:
        return hash(key) % self.shards

    def get(self, key: Hashable, now: Optional[float] = None) -> Optional[T]:
        current = time.monotonic() if now is None else float(now)
        index = self._index(key)
        with self._locks[index]:
            bucket = self._data[index]
            found = bucket.get(key)
            if found is None:
                return None
            expires_at, value = found
            if expires_at <= current:
                del bucket[key]
                return None
            bucket.move_to_end(key)
            return value

    def set(self, key: Hashable, value: T, ttl_seconds: float = 60.0,
            now: Optional[float] = None) -> None:
        current = time.monotonic() if now is None else float(now)
        index = self._index(key)
        with self._locks[index]:
            bucket = self._data[index]
            bucket[key] = (current + max(0.001, float(ttl_seconds)), value)
            bucket.move_to_end(key)
            self._prune_locked(index, current)

    def pop(self, key: Hashable) -> Optional[T]:
        index = self._index(key)
        with self._locks[index]:
            found = self._data[index].pop(key, None)
        return found[1] if found is not None else None

    def contains(self, key: Hashable, now: Optional[float] = None) -> bool:
        return self.get(key, now) is not None

    def prune(self, now: Optional[float] = None) -> int:
        current = time.monotonic() if now is None else float(now)
        removed = 0
        for index in range(self.shards):
            with self._locks[index]:
                removed += self._prune_locked(index, current)
        return removed

    def __len__(self) -> int:
        total = 0
        for index in range(self.shards):
            with self._locks[index]:
                total += len(self._data[index])
        return total

    def _prune_locked(self, index: int, now: float) -> int:
        bucket = self._data[index]
        removed = 0
        for key, (expires_at, _) in list(bucket.items()):
            if expires_at <= now:
                del bucket[key]
                removed += 1
        while len(bucket) > self._caps[index]:
            bucket.popitem(last=False)
            removed += 1
        return removed


class ReplayNonceCache:
    """One-time nonce filter backed by a bounded TTL cache."""

    def __init__(self, max_entries: int = 100_000, ttl_seconds: float = 900.0) -> None:
        self.ttl_seconds = max(1.0, float(ttl_seconds))
        self._cache: ShardedTTLCache[bool] = ShardedTTLCache(max_entries=max_entries)

    def claim(self, nonce: str, now: Optional[float] = None) -> bool:
        """Atomically claim *nonce*; return False when it was already used."""
        if not nonce:
            return False
        current = time.monotonic() if now is None else float(now)
        # The nonce is cryptographically random; the cache's shard lock gives
        # us a short critical section while preserving the no-global-lock path.
        index = self._cache._index(nonce)
        lock = self._cache._locks[index]
        with lock:
            bucket = self._cache._data[index]
            found = bucket.get(nonce)
            if found is not None and found[0] > current:
                return False
            bucket[nonce] = (current + self.ttl_seconds, True)
            bucket.move_to_end(nonce)
            self._cache._prune_locked(index, current)
            return True


def prefix_for_ip(remote_ip: str, ipv4_prefix: int = 24, ipv6_prefix: int = 64) -> str:
    """Return a canonical privacy-safe routing prefix."""
    import ipaddress

    try:
        address = ipaddress.ip_address(remote_ip)
        prefix = ipv4_prefix if address.version == 4 else ipv6_prefix
        return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False).network_address) + f"/{prefix}"
    except ValueError:
        return "invalid/0"


def stable_bucket(value: str, buckets: int = 64) -> int:
    """Fast deterministic shard selection independent of Python hash randomization."""
    digest = hashlib.blake2s(value.encode("utf-8"), digest_size=4).digest()
    return int.from_bytes(digest, "big") % max(1, int(buckets))
