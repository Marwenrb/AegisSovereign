"""Active deception/tarpit helpers for high-confidence automation.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional


@dataclass(frozen=True, slots=True)
class DeceptionResponse:
    """Structurally realistic synthetic response without attacker diagnostics."""

    status_code: int
    body: bytes
    delay_ms: int
    headers: Mapping[str, str]


class DeceptionTarpit:
    """Generate deterministic decoys and bounded micro-jitter."""

    def __init__(self, secret_key: str, minimum_delay_ms: int = 40, maximum_delay_ms: int = 250) -> None:
        self._secret = secret_key.encode("utf-8")
        self.minimum_delay_ms = max(0, int(minimum_delay_ms))
        self.maximum_delay_ms = max(self.minimum_delay_ms, int(maximum_delay_ms))

    def delay_for(self, subject: str, risk_score: float) -> int:
        digest = hashlib.blake2s(self._secret + subject.encode("utf-8"), digest_size=2).digest()
        spread = self.maximum_delay_ms - self.minimum_delay_ms
        risk = max(0.0, min(1.0, float(risk_score)))
        return min(self.maximum_delay_ms,
                   self.minimum_delay_ms + int.from_bytes(digest, "big") % (spread + 1) + int(risk * 20.0))

    def decoy(self, *, subject: str = "", risk_score: float = 0.9,
              payload: Optional[Mapping[str, Any]] = None) -> DeceptionResponse:
        delay = self.delay_for(subject, risk_score)
        body = dict(payload or {"status": "accepted", "request_id": hashlib.sha256(
            f"{subject}:{delay}".encode("utf-8")).hexdigest()[:16]})
        return DeceptionResponse(200, json.dumps(body, separators=(",", ":")).encode("utf-8"), delay,
                                 {"Content-Type": "application/json", "Cache-Control": "no-store",
                                  "X-Aegis-Deception": "1"})

    @staticmethod
    def sleep(response: DeceptionResponse) -> None:
        time.sleep(response.delay_ms / 1000.0)


def generate_decoy_response(secret_key: str, subject: str = "", risk_score: float = 0.9) -> DeceptionResponse:
    return DeceptionTarpit(secret_key).decoy(subject=subject, risk_score=risk_score)
