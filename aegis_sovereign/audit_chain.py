"""Tamper-evident append-only audit hash chain."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List


@dataclass(frozen=True, slots=True)
class ChainLink:
    event_id: str
    previous_hash: str
    event_hash: str
    sequence: int


class MerkleAuditChain:
    """Hash chain with a Merkle-style root over the current audit window."""

    def __init__(self, max_links: int = 50_000) -> None:
        self.max_links = max(1, int(max_links))
        self._links: List[ChainLink] = []
        self._root = "0" * 64
        self._initial_hash = "0" * 64
        self._lock = threading.RLock()

    def append(self, event_id: str, payload: Dict[str, Any]) -> ChainLink:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        with self._lock:
            previous = self._links[-1].event_hash if self._links else self._root
            digest = hashlib.sha256(f"{previous}|{canonical}".encode("utf-8")).hexdigest()
            link = ChainLink(event_id, previous, digest, len(self._links))
            self._links.append(link)
            if len(self._links) > self.max_links:
                popped = self._links.pop(0)
                self._initial_hash = popped.event_hash
                self._links = [ChainLink(item.event_id, item.previous_hash, item.event_hash, i)
                               for i, item in enumerate(self._links)]
            self._root = self._calculate_root_locked()
            return link

    def root(self) -> str:
        with self._lock:
            return self._root

    def links(self) -> List[ChainLink]:
        with self._lock:
            return list(self._links)

    def verify(self) -> bool:
        with self._lock:
            if not self._links:
                return self._root == "0" * 64
            previous = self._initial_hash
            for item in self._links:
                if item.previous_hash != previous:
                    return False
                previous = item.event_hash
            return self._root == self._calculate_root_locked()

    def _calculate_root_locked(self) -> str:
        if not self._links:
            return "0" * 64
        level = [item.event_hash for item in self._links]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [hashlib.sha256((level[i] + level[i + 1]).encode("ascii")).hexdigest()
                     for i in range(0, len(level), 2)]
        return level[0]
