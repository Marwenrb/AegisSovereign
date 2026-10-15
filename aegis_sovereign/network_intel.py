"""AegisSovereign P1 - Network intelligence core.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional

from .state import ShardedTTLCache

logger = logging.getLogger(__name__)

# --- Passive OS fingerprint heuristics --------------------------------------
PASSIVE_OS_SIGNATURES = {
    "linux": {"initial_ttl": 64, "window_size": 64240},
    "windows": {"initial_ttl": 128, "window_size": 65535},
    "macos": {"initial_ttl": 64, "window_size": 65160},
    "ios": {"initial_ttl": 64, "window_size": 65160},
    "android": {"initial_ttl": 64, "window_size": 65535},
}

# Cloud / datacenter ASNs (strong risk prior on sensitive endpoints).
DATA_CENTER_ASNS = {13335, 16509, 16623, 16631, 16881, 16884, 20940, 26496, 15169}
MOBILE_ASNS = {28573, 21928, 31098, 3}
TOR_EXIT_ASNS = {16509, 396507}


@dataclass(slots=True)
class Location:
    country: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""


@dataclass(slots=True)
class NetworkIntel:
    """Fused network evidence package for one request."""

    remote_ip: str
    location: Location = field(default_factory=Location)
    asn: Optional[int] = None
    asn_name: str = ""
    is_datacenter: bool = False
    is_residential: bool = False
    is_vpn: bool = False
    is_shared_egress: bool = False
    passive_os_match: str = "unknown"
    os_claimed: str = ""
    rtt_ms: float = 0.0
    rtt_geography_consistent: bool = True
    reputation_score: float = 0.5
    risk_features: Dict[str, float] = field(default_factory=dict)
    prefix: str = ""
    asn_class: str = "unknown"
    is_tor_exit: bool = False
    is_residential_proxy: bool = False


class _GeoIPBackend:
    """Pluggable GeoIP backend. Subclasses a real mmdb reader."""

    def country(self, ip: str) -> str:
        return ""

    def city(self, ip: str) -> str:
        return ""

    def latitude(self, ip: str) -> float:
        return 0.0

    def longitude(self, ip: str) -> float:
        return 0.0

    def timezone(self, ip: str) -> str:
        return ""

    def asn(self, ip: str) -> tuple[int, str]:
        return (0, "")

    def is_datacenter(self, ip: str) -> bool:
        return False

    def is_residential(self, ip: str) -> bool:
        return False

    def is_vpn(self, ip: str) -> bool:
        return False


class GeoIP:
    """GeoIP wrapper that delegates to a given backend or a no-op fallback."""

    def __init__(self, backend: Optional[_GeoIPBackend] = None):
        self._backend = backend if backend is not None else _GeoIPBackend()

    def country(self, ip: str) -> str:
        return self._backend.country(ip)

    def city(self, ip: str) -> str:
        return self._backend.city(ip)

    def latitude(self, ip: str) -> float:
        return self._backend.latitude(ip)

    def longitude(self, ip: str) -> float:
        return self._backend.longitude(ip)

    def timezone(self, ip: str) -> str:
        return self._backend.timezone(ip)

    def asn(self, ip: str) -> tuple[int, str]:
        return self._backend.asn(ip)

    def is_datacenter(self, ip: str) -> bool:
        return self._backend.is_datacenter(ip)

    def is_residential(self, ip: str) -> bool:
        return self._backend.is_residential(ip)

    def is_vpn(self, ip: str) -> bool:
        return self._backend.is_vpn(ip)


class NetworkIntelligence:
    """Computes fused network evidence for one request."""

    def __init__(self, geo: Optional[GeoIP] = None):
        self.geo = geo if geo is not None else GeoIP()
        self._prefix_seen: ShardedTTLCache[set[str]] = ShardedTTLCache(max_entries=10_000, shards=16)

    def assess(
        self,
        remote_ip: str,
        *,
        claimed_os: str = "",
        claimed_country: str = "",
        rtt_ms: float = 0.0,
    ) -> NetworkIntel:
        location = Location(
            country=self.geo.country(remote_ip),
            city=self.geo.city(remote_ip),
            latitude=self.geo.latitude(remote_ip),
            longitude=self.geo.longitude(remote_ip),
            timezone=self.geo.timezone(remote_ip),
        )
        asn, asn_name = self.geo.asn(remote_ip)
        is_dc = self.geo.is_datacenter(remote_ip)
        is_res = self.geo.is_residential(remote_ip)
        is_vpn = self.geo.is_vpn(remote_ip)
        is_shared = is_res or is_vpn or asn in DATA_CENTER_ASNS
        prefix = self.prefix(remote_ip)
        asn_class = self.classify_asn(asn, is_dc, is_res, is_vpn)
        is_tor = asn in TOR_EXIT_ASNS
        is_res_proxy = asn_class == "residential_proxy"
        prior_ips = set(self._prefix_seen.get(prefix) or set())
        prior_ips.add(remote_ip)
        self._prefix_seen.set(prefix, prior_ips, ttl_seconds=900.0)
        rotation = len(prior_ips) >= 4

        os_match = self._passive_os_match(claimed_os)

        rtt_consistent = self._rtt_consistent(claimed_country, rtt_ms)

        rep = 0.5
        if is_dc:
            rep = 0.75
        elif is_res:
            rep = 0.12
        elif is_vpn:
            rep = 0.55
        if is_tor:
            rep = 0.95
        elif is_res_proxy:
            rep = min(0.9, rep + 0.35)
        if rotation:
            rep = min(1.0, rep + 0.2)
        if claimed_country and claimed_country != location.country:
            rep = min(0.95, rep + 0.25)

        feats = {
            "is_datacenter": 1.0 if is_dc else 0.0,
            "is_residential": 1.0 if is_res else 0.0,
            "is_vpn": 1.0 if is_vpn else 0.0,
            "is_shared_egress": 1.0 if is_shared else 0.0,
            "country_mismatch": 1.0 if claimed_country and claimed_country != location.country else 0.0,
            "passive_os_match": 1.0 if os_match else 0.0,
            "rtt_consistent": 1.0 if rtt_consistent else 0.0,
            "rapid_prefix_rotation": 1.0 if rotation else 0.0,
            "tor_exit": 1.0 if is_tor else 0.0,
            "residential_proxy": 1.0 if is_res_proxy else 0.0,
        }

        return NetworkIntel(
            remote_ip=remote_ip,
            location=location,
            asn=asn,
            asn_name=asn_name,
            is_datacenter=is_dc,
            is_residential=is_res,
            is_vpn=is_vpn,
            is_shared_egress=is_shared,
            passive_os_match=os_match,
            os_claimed=claimed_os,
            rtt_ms=rtt_ms,
            rtt_geography_consistent=rtt_consistent,
            reputation_score=rep,
            risk_features=feats,
            prefix=prefix,
            asn_class=asn_class,
            is_tor_exit=is_tor,
            is_residential_proxy=is_res_proxy,
        )

    @staticmethod
    def prefix(remote_ip: str) -> str:
        try:
            address = ipaddress.ip_address(remote_ip)
            length = 24 if address.version == 4 else 64
            return str(ipaddress.ip_network(f"{address}/{length}", strict=False))
        except ValueError:
            return "invalid/0"

    @staticmethod
    def classify_asn(asn: Optional[int], datacenter: bool, residential: bool, vpn: bool) -> str:
        if asn in TOR_EXIT_ASNS:
            return "tor_exit"
        if residential and vpn:
            return "residential_proxy"
        if vpn:
            return "vpn_proxy"
        if datacenter or asn in DATA_CENTER_ASNS:
            return "cloud_datacenter"
        if asn in MOBILE_ASNS:
            return "mobile_isp"
        if residential:
            return "residential"
        return "unknown"

    @staticmethod
    def geo_timezone_language_consistent(network: NetworkIntel, timezone: str,
                                         languages: Iterable[str]) -> bool:
        values = list(languages)
        if network.location.timezone and timezone and network.location.timezone != timezone:
            return False
        country = network.location.country.upper()
        if not country or not values:
            return True
        return any(str(language).split("-")[0].upper() == country for language in values)

    def _passive_os_match(self, claimed_os: str) -> str:
        if not claimed_os:
            return "unknown"
        claimed = claimed_os.lower()
        if "windows" in claimed:
            expected = PASSIVE_OS_SIGNATURES["windows"]
        elif "mac" in claimed or "ios" in claimed or "darwin" in claimed:
            expected = PASSIVE_OS_SIGNATURES["macos"]
        else:
            expected = PASSIVE_OS_SIGNATURES["linux"]
        # Real deployment compares stack signature (TTL/window) to the above.
        # This proxy fields a deterministic result for the demo.
        return "match"

    @staticmethod
    def _rtt_consistent(claimed_country: str, rtt_ms: float) -> bool:
        if not claimed_country or rtt_ms <= 0:
            return True
        return rtt_ms <= 400.0

    @staticmethod
    def aggregate_subnet_tail(ips: Iterable[str], tail: int = 64) -> Dict[str, int]:
        anchors: Dict[str, int] = {}
        for ip in ips:
            try:
                addr = struct.unpack(">I", socket.inet_aton(ip))[0]
            except Exception:
                continue
            anchor = addr >> (32 - min(32, tail))
            anchors[anchor] = anchors.get(anchor, 0) + 1
        return anchors
