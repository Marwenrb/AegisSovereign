"""AegisSovereign P2 - Transport fingerprints.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)

JA4 family as the primary TLS fingerprint. JA4 sorts ciphers and extensions
before hashing (unlike the unstable JA3), encodes protocol version, SNI
presence, ALPN, signature algorithms, and the hybrid PQ key share.

Additive JA4+ traits (used selectively; confirm FoxIO licensing before
embedding JA4S/JA4H/JA4T/JA4L in a product):
    - JA4S   : server hello analysis
    - JA4H   : HTTP request line + header order
    - JA4T   : TCP initial window / MSS / option ordering
    - JA4L   : latency profile

QUIC / HTTP/3 fingerprints are computed from QUIC transport parameters and
HTTP/3 SETTINGS, in addition to HTTP/2 SETTINGS.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# --- Recognised TLS versions ------------------------------------------------
TLS_VERSIONS = {
    "TLSv1.2": 0x0303,
    "TLSv1.3": 0x0304,
}

# --- JA4 cipher suite short names --------------------------------------------
# (IANA name -> JA4 short) 
JA4_CIPHERS = {
    "TLS_AES_128_GCM_SHA256": "AES128GCM",
    "TLS_AES_256_GCM_SHA384": "AES256GCM",
    "TLS_CHACHA20_POLY1305_SHA256": "CHACHA20",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "ECDHAES128",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHAES128",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "ECDHAES256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "ECDHAES256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "ECDCHACHA",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "ECDCHACHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": "ECDHAES128CBC",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": "ECDHAES128CBC",
}

JA4_EXTENSIONS = {
    "server_name": "sni",
    "supported_groups": "grps",
    "signature_algorithms": "sig",
    "ALPN": "alpn",
    "status_request": "sr",
    "session_ticket": "st",
    "pre_shared_key": "psk",
    "early_data": "ed",
    "extended_master_secret": "ems",
    "supported_versions": "vers",
    "cookie": "cookie",
    "psk_key_exchange_modes": "pskkm",
    "token": "tok",
}


@dataclass(slots=True)
class JA4Hash:
    ja4: str
    ja4_client: str
    ja4_server: Optional[str] = None
    ja4_table: Optional[str] = None
    ja4_latency: Optional[str] = None
    tls_version: str = ""
    sni_present: bool = False
    alpn: List[str] = field(default_factory=list)
    ciphers: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    signature_algorithms: List[str] = field(default_factory=list)
    key_shares: List[str] = field(default_factory=list)
    hybrid_pq_key_share: bool = False


def ja4_from_dict(
    *,
    ciphers: List[str],
    extensions: List[str],
    tls_version: str = "TLSv1.3",
    sni_present: bool = False,
    alpn: List[str] = None,
    signature_algorithms: List[str] = None,
    key_shares: List[str] = None,
    include_hybrid_pq: bool = False,
) -> JA4Hash:
    """Compute JA4 from structured client-hello data.

    JA4 sorts all fields before hashing, which is what makes it stable against
    the extension-order randomisation that breaks JA3.
    """
    alpn = alpn or []
    signature_algorithms = signature_algorithms or []
    key_shares = key_shares or []

    cert = [
        "v" + tls_version.replace("TLS", "").replace(".", ""),
        "sni" if sni_present else "nosni",
        ",".join(sorted(alpn)) if alpn else "noalpn",
        ",".join(sorted(ciphers)),
        ",".join(sorted(extensions)),
        ",".join(sorted(signature_algorithms)),
    ]
    base = "|".join(cert)

    hybrid = ""
    if include_hybrid_pq and any("MLKEM" in k for k in key_shares):
        hybrid = ",pqmlkem"
    elif include_hybrid_pq:
        hybrid = ",nompkem"

    ja4 = "J4" + hashlib.sha256(base.encode("utf-8")).hexdigest()[:10]
    ja4_client = ja4 + hybrid

    return JA4Hash(
        ja4=ja4,
        ja4_client=ja4_client,
        ja4_server=None,
        ja4_table=None,
        ja4_latency=None,
        tls_version=tls_version,
        sni_present=sni_present,
        alpn=alpn,
        ciphers=ciphers,
        extensions=extensions,
        signature_algorithms=signature_algorithms,
        key_shares=key_shares,
        hybrid_pq_key_share=any("MLKEM" in k for k in key_shares),
    )


def ja4_from_raw(
    ciphers: List[str],
    extensions: List[str],
    tls_version: str = "TLSv1.3",
    sni_present: bool = False,
    alpn: List[str] = None,
    signature_algorithms: List[str] = None,
) -> JA4Hash:
    """Convenience entry point; delegates to :func:`ja4_from_dict`."""
    return ja4_from_dict(
        ciphers=ciphers,
        extensions=extensions,
        tls_version=tls_version,
        sni_present=sni_present,
        alpn=alpn,
        signature_algorithms=signature_algorithms,
    )


def http2_settings_fingerprint(settings: Dict[str, int]) -> str:
    """Hash the ordered set of HTTP/2 SETTINGS for cross-client coherence."""
    ordered = sorted(settings.items())
    canonical = "|".join(f"{k}={v}" for k, v in ordered)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def quic_fingerprint(
    *,
    initial_packet: bytes = b"",
    transport_params: Dict[str, int] = None,
    http3_settings: Dict[str, int] = None,
) -> str:
    """Quic/trip-style fingerprint.

    Encodes the initial packet structure plus QUIC transport parameters.
    """
    transport_params = transport_params or {}
    http3_settings = http3_settings or {}

    # Quic key share detection (hybrid X25519MLKEM768)
    has_pq = any("MLKEM" in k for k in transport_params)

    canonical = f"pkt:{initial_packet.hex()}|tp:{sorted(transport_params.items())}|h3:{sorted(http3_settings.items())}"
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return f"Q4{digest}" + ("P" if has_pq else "")
