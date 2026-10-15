"""AegisSovereign P3 — Client integrity: HMAC-bound signed challenges.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)

Wire format (symmetrical issue/verify)::

    AEGISINTEG.{session_id}.{issued_at}.{expires_at}.{nonce}.{claims_hash}.{signature}

where ``claims_hash`` is the hex SHA-256 of canonical JSON claims and
``signature`` is ``HMAC-SHA256(secret, payload)`` over::

    session_id|tls_channel_id|issued_at|expires_at|nonce|claims_hash
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

CHALLENGE_RESPONSE_PREFIX = "AEGISINTEG"


def canonical_claims_hash(claims: Optional[Dict[str, Any]]) -> str:
    """Deterministic hex digest of canonical JSON claims."""
    canonical = json.dumps(claims or {}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _hmac_hex(secret_key: str, payload: str) -> str:
    return hmac.new(
        secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()


@dataclass(slots=True)
class IntegrityToken:
    """Server-side signed integrity token bound to session + TLS channel."""

    token: str
    session_id: str
    tls_channel_id: str
    issued_at: int
    expires_at: int
    signature: str
    nonce: str
    claims_hash: str = ""


class SignedChallenge:
    """Server-rotated, signed, short-lived TLS-bound challenge bundle."""

    def __init__(
        self,
        secret_key: str,
        *,
        ttl_seconds: int = 5,
        buffer_seconds: int = 15,
    ) -> None:
        self.secret_key = secret_key
        self.ttl_seconds = ttl_seconds
        self.buffer_seconds = buffer_seconds

    def issue(
        self,
        *,
        session_id: str,
        tls_channel_id: str,
        claims: Optional[Dict[str, Any]] = None,
    ) -> IntegrityToken:
        issued_at = int(time.time())
        expires_at = issued_at + self.ttl_seconds
        nonce = secrets.token_urlsafe(16)
        chash = canonical_claims_hash(claims)
        payload = (
            f"{session_id}|{tls_channel_id}|{issued_at}|{expires_at}|{nonce}|{chash}"
        )
        signature = _hmac_hex(self.secret_key, payload)
        token = (
            f"{CHALLENGE_RESPONSE_PREFIX}.{session_id}.{issued_at}."
            f"{expires_at}.{nonce}.{chash}.{signature}"
        )
        return IntegrityToken(
            token=token,
            session_id=session_id,
            tls_channel_id=tls_channel_id,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature,
            nonce=nonce,
            claims_hash=chash,
        )

    @staticmethod
    def verify(
        raw_token: str,
        *,
        secret_key: str,
        session_id: str,
        tls_channel_id: str,
        claims: Optional[Dict[str, Any]] = None,
        now: Optional[int] = None,
        buffer_seconds: int = 15,
    ) -> Tuple[bool, str]:
        if not raw_token or not raw_token.startswith(CHALLENGE_RESPONSE_PREFIX):
            return False, "invalid_prefix"
        parts = raw_token.split(".")
        if len(parts) != 7:
            return False, "invalid_format"
        _, tok_session, s_issued, s_expires, nonce, chash, signature = parts
        if tok_session != session_id:
            return False, "session_mismatch"
        try:
            issued_at = int(s_issued)
            expires_at = int(s_expires)
        except ValueError:
            return False, "bad_expiry"
        if claims is not None:
            expected_chash = canonical_claims_hash(claims)
            if not hmac.compare_digest(expected_chash, chash):
                return False, "claims_mismatch"
        payload = (
            f"{session_id}|{tls_channel_id}|{issued_at}|{expires_at}|{nonce}|{chash}"
        )
        expected = _hmac_hex(secret_key, payload)
        if not hmac.compare_digest(expected, signature):
            return False, "signature_mismatch"
        cur = int(now) if now is not None else int(time.time())
        if cur > expires_at + int(buffer_seconds):
            return False, "expired"
        if cur < issued_at - int(buffer_seconds):
            return False, "not_yet_valid"
        return True, "ok"
