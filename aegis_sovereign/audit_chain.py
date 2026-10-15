"""Tamper-evident append-only audit hash chain.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

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
        self._frontier: List[str | None] = []
        self._lock = threading.RLock()

    def append(self, event_id: str, payload: Dict[str, Any]) -> ChainLink:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        with self._lock:
            previous = self._links[-1].event_hash if self._links else self._root
            digest = hashlib.sha256(f"{previous}|{canonical}".encode("utf-8")).hexdigest()
            link = ChainLink(event_id, previous, digest, len(self._links))
            self._links.append(link)
            self._add_leaf_locked(digest)
            if len(self._links) > self.max_links:
                popped = self._links.pop(0)
                self._initial_hash = popped.event_hash
                self._links = [ChainLink(item.event_id, item.previous_hash, item.event_hash, i)
                               for i, item in enumerate(self._links)]
                self._frontier = []
                for item in self._links:
                    self._add_leaf_locked(item.event_hash)
            self._root = self._frontier_root_locked()
            return link

    def root(self) -> str:
        with self._lock:
            return self._root

    def links(self) -> List[ChainLink]:
        with self._lock:
            return list(self._links)

    def clear(self) -> None:
        with self._lock:
            self._links.clear()
            self._root = "0" * 64
            self._initial_hash = "0" * 64
            self._frontier = []

    def verify(self) -> bool:
        with self._lock:
            if not self._links:
                return self._root == "0" * 64
            previous = self._initial_hash
            for item in self._links:
                if item.previous_hash != previous:
                    return False
                previous = item.event_hash
            return self._root == self._rebuild_root_locked()

    def _add_leaf_locked(self, leaf: str) -> None:
        carry = leaf
        level = 0
        while level < len(self._frontier) and self._frontier[level] is not None:
            carry = hashlib.sha256((self._frontier[level] + carry).encode("ascii")).hexdigest()
            self._frontier[level] = None
            level += 1
        if level == len(self._frontier):
            self._frontier.append(carry)
        else:
            self._frontier[level] = carry

    def _frontier_root_locked(self) -> str:
        values = [value for value in self._frontier if value is not None]
        if not values:
            return "0" * 64
        root = values[-1]
        for value in reversed(values[:-1]):
            root = hashlib.sha256((value + root).encode("ascii")).hexdigest()
        return root

    def _rebuild_root_locked(self) -> str:
        frontier: List[str | None] = []
        for item in self._links:
            carry = item.event_hash
            level = 0
            while level < len(frontier) and frontier[level] is not None:
                carry = hashlib.sha256((frontier[level] + carry).encode("ascii")).hexdigest()
                frontier[level] = None
                level += 1
            if level == len(frontier):
                frontier.append(carry)
            else:
                frontier[level] = carry
        values = [value for value in frontier if value is not None]
        if not values:
            return "0" * 64
        root = values[-1]
        for value in reversed(values[:-1]):
            root = hashlib.sha256((value + root).encode("ascii")).hexdigest()
        return root
