"""Stateless HMAC-signed proof-of-work challenges (P8)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True, slots=True)
class PoWChallenge:
    token: str
    challenge: str
    issued_at: int
    expires_at: int
    difficulty: int


def _leading_zero_bits(digest: bytes) -> int:
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        count += 8 - byte.bit_length()
        break
    return count


class AegisPoW:
    """Issues and verifies bounded-cost SHA-256 puzzles."""

    def __init__(self, secret_key: str, ttl_seconds: int = 120,
                 min_difficulty: int = 14, max_difficulty: int = 28) -> None:
        self.secret_key = secret_key.encode("utf-8")
        self.ttl_seconds = max(1, int(ttl_seconds))
        self.min_difficulty = max(1, int(min_difficulty))
        self.max_difficulty = max(self.min_difficulty, int(max_difficulty))

    def difficulty_for(self, risk_score: float, attack_pressure: float = 0.0) -> int:
        score = max(0.0, min(1.0, float(risk_score)))
        pressure = max(0.0, min(1.0, float(attack_pressure)))
        value = self.min_difficulty + int(round(score * 6.0 + pressure * 8.0))
        return min(self.max_difficulty, max(self.min_difficulty, value))

    def issue(self, *, risk_score: float = 0.5, attack_pressure: float = 0.0,
              subject: str = "", now: Optional[int] = None) -> PoWChallenge:
        issued = int(time.time()) if now is None else int(now)
        expires = issued + self.ttl_seconds
        difficulty = self.difficulty_for(risk_score, attack_pressure)
        challenge = secrets.token_urlsafe(18)
        payload = self._payload(challenge, issued, expires, difficulty, subject)
        signature = hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        token = f"AEGISPOW.1.{issued}.{expires}.{difficulty}.{challenge}.{signature}"
        return PoWChallenge(token, challenge, issued, expires, difficulty)

    def verify(self, token: str, solution: str, *, subject: str = "",
               now: Optional[int] = None) -> Tuple[bool, str]:
        parts = token.split(".") if token else []
        if len(parts) != 7 or parts[0] != "AEGISPOW" or parts[1] != "1":
            return False, "invalid_format"
        try:
            issued, expires, difficulty = int(parts[2]), int(parts[3]), int(parts[4])
        except ValueError:
            return False, "invalid_numeric_field"
        challenge, signature = parts[5], parts[6]
        expected = hmac.new(self.secret_key,
                            self._payload(challenge, issued, expires, difficulty, subject).encode("utf-8"),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return False, "signature_mismatch"
        current = int(time.time()) if now is None else int(now)
        if current > expires:
            return False, "expired"
        if current < issued:
            return False, "not_yet_valid"
        if not solution:
            return False, "missing_solution"
        digest = hashlib.sha256(f"{challenge}:{solution}".encode("utf-8")).digest()
        if _leading_zero_bits(digest) < difficulty:
            return False, "insufficient_work"
        return True, "ok"

    @staticmethod
    def solve(challenge: PoWChallenge, *, max_attempts: int = 10_000_000) -> str:
        """Reference solver used by tests and the browser SDK."""
        for attempt in range(max(1, int(max_attempts))):
            candidate = str(attempt)
            digest = hashlib.sha256(f"{challenge.challenge}:{candidate}".encode("utf-8")).digest()
            if _leading_zero_bits(digest) >= challenge.difficulty:
                return candidate
        raise RuntimeError("proof-of-work solution not found within max_attempts")

    @staticmethod
    def _payload(challenge: str, issued: int, expires: int, difficulty: int, subject: str) -> str:
        return f"{challenge}|{issued}|{expires}|{difficulty}|{subject}"
