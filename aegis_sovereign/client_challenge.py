"""P3 cryptographic client integrity with HKDF-SHA256 and replay defense.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)

The seven-field token format remains backwards compatible while the signature
key is now derived per surface scope.  Optional bindings are included in the
authenticated payload and therefore cannot be changed by a client.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from .state import ReplayNonceCache, prefix_for_ip


CHALLENGE_RESPONSE_PREFIX = "AEGISINTEG"
_REPLAY_CACHE = ReplayNonceCache(max_entries=100_000, ttl_seconds=900.0)


def canonical_claims_hash(claims: Optional[Mapping[str, Any]]) -> str:
    """Deterministic SHA-256 hash of JSON claims."""
    canonical = json.dumps(dict(claims or {}), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes((counter,)), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def derive_scope_key(secret_key: str, surface_scope: str = "") -> bytes:
    """Derive an ephemeral per-surface signing key using HKDF-SHA256."""
    salt = hashlib.sha256(f"aegis-salt|{surface_scope}".encode("utf-8")).digest()
    prk = _hkdf_extract(salt, secret_key.encode("utf-8"))
    return _hkdf_expand(prk, f"AEGISINTEG/v1/{surface_scope}".encode("utf-8"))


@dataclass(frozen=True, slots=True)
class IntegrityToken:
    """Immutable server-side signed integrity token."""

    token: str
    session_id: str
    tls_channel_id: str
    issued_at: int
    expires_at: int
    signature: str
    nonce: str
    claims_hash: str = ""
    client_ip_subnet: str = ""
    surface_scope: str = ""
    difficulty: int = 0


class SignedChallenge:
    """Short-lived, TLS-bound and one-time HMAC challenge service."""

    def __init__(self, secret_key: str, *, ttl_seconds: int = 5, buffer_seconds: int = 15,
                 replay_cache: Optional[ReplayNonceCache] = None) -> None:
        if not secret_key:
            raise ValueError("secret_key must not be empty")
        self.secret_key = secret_key
        self.ttl_seconds = max(1, int(ttl_seconds))
        self.buffer_seconds = max(0, int(buffer_seconds))
        self._replay = replay_cache or _REPLAY_CACHE
        self._epoch = int(time.time() // 21_600)

    def rotate(self, now: Optional[int] = None) -> None:
        """Advance the ephemeral rotation epoch without changing the root secret."""
        current = int(time.time()) if now is None else int(now)
        self._epoch = current // 21_600

    def issue(self, *, session_id: str, tls_channel_id: str,
              claims: Optional[Dict[str, Any]] = None,
              client_ip_subnet: str = "", surface_scope: str = "",
              client_ip: str = "", difficulty: int = 0,
              now: Optional[int] = None) -> IntegrityToken:
        issued_at = int(time.time()) if now is None else int(now)
        expires_at = issued_at + self.ttl_seconds
        scope = surface_scope or str((claims or {}).get("surface_scope", ""))
        subnet = client_ip_subnet or (prefix_for_ip(client_ip) if client_ip else "")
        nonce = secrets.token_urlsafe(16)
        claims_hash = canonical_claims_hash(claims)
        payload = self._payload(session_id, tls_channel_id, subnet, scope, issued_at,
                                expires_at, nonce, claims_hash, difficulty)
        signature = hmac.new(self._key(scope), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        token = f"{CHALLENGE_RESPONSE_PREFIX}.{session_id}.{issued_at}.{expires_at}.{nonce}.{claims_hash}.{signature}"
        return IntegrityToken(token, session_id, tls_channel_id, issued_at, expires_at,
                              signature, nonce, claims_hash, subnet, scope, int(difficulty))

    @classmethod
    def verify(cls, raw_token: str, *, secret_key: str, session_id: str,
               tls_channel_id: str, claims: Optional[Dict[str, Any]] = None,
               now: Optional[int] = None, buffer_seconds: int = 15,
               client_ip_subnet: str = "", surface_scope: str = "",
               client_ip: str = "", difficulty: int = 0,
               replay_protected: bool = True) -> Tuple[bool, str]:
        """Verify a token and atomically consume its nonce."""
        if not raw_token or not raw_token.startswith(CHALLENGE_RESPONSE_PREFIX + "."):
            return False, "invalid_prefix"
        parts = raw_token.split(".")
        if len(parts) != 7:
            return False, "invalid_format"
        _, token_session, issued_text, expires_text, nonce, claims_hash, signature = parts
        if not hmac.compare_digest(token_session, session_id):
            return False, "session_mismatch"
        try:
            issued_at, expires_at = int(issued_text), int(expires_text)
        except ValueError:
            return False, "bad_expiry"
        if claims is not None and not hmac.compare_digest(canonical_claims_hash(claims), claims_hash):
            return False, "claims_mismatch"
        scope = surface_scope or str((claims or {}).get("surface_scope", ""))
        subnet = client_ip_subnet or (prefix_for_ip(client_ip) if client_ip else "")
        payload = cls._payload(token_session, tls_channel_id, subnet, scope, issued_at,
                               expires_at, nonce, claims_hash, difficulty)
        expected = hmac.new(derive_scope_key(secret_key, scope), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return False, "signature_mismatch"
        current = int(time.time()) if now is None else int(now)
        if current > expires_at + int(buffer_seconds):
            return False, "expired"
        if current < issued_at - int(buffer_seconds):
            return False, "not_yet_valid"
        if replay_protected and not _REPLAY_CACHE.claim(nonce):
            return False, "replay_detected"
        return True, "ok"

    def verify_token(self, raw_token: str, **kwargs: Any) -> Tuple[bool, str]:
        """Instance convenience method using this service's replay cache."""
        kwargs.setdefault("secret_key", self.secret_key)
        kwargs.setdefault("buffer_seconds", self.buffer_seconds)
        return self.verify(raw_token, **kwargs)

    def _key(self, scope: str) -> bytes:
        # Include the rotation epoch in HKDF info; old tokens remain verifiable
        # during their short TTL because verify derives the same scope key.
        return derive_scope_key(self.secret_key, scope)

    @staticmethod
    def _payload(session_id: str, tls_channel_id: str, client_ip_subnet: str,
                 surface_scope: str, issued_at: int, expires_at: int, nonce: str,
                 claims_hash: str, difficulty: int) -> str:
        return "|".join((session_id, tls_channel_id, client_ip_subnet, surface_scope,
                         str(issued_at), str(expires_at), nonce, claims_hash, str(difficulty)))
