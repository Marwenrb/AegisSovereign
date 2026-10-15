"""AegisSovereign deterministic mock GeoIP backends for testing.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)

These back-ends are pure functions over the IP address tuple so that tests
never need a real GeoIP database (or network access) to exercise the
network-intelligence layer.
"""

from __future__ import annotations

from .network_intel import _GeoIPBackend


class MockGeoBackend(_GeoIPBackend):
    """Returns a fixed country/ASN for every IP (deterministic)."""

    def __init__(
        self,
        country: str = "US",
        asn: int = 12398,
        asn_name: str = "Example ISP",
        datacenter: bool = False,
        residential: bool = False,
        vpn: bool = False,
    ):
        super().__init__()
        self.country_code = country
        self._asn_value = asn
        self.asn_name = asn_name
        self._dc = datacenter
        self._res = residential
        self._vpn = vpn

    def country(self, ip: str) -> str:
        return self.country_code

    def city(self, ip: str) -> str:
        return "MockCity"

    def latitude(self, ip: str) -> float:
        return 40.7128

    def longitude(self, ip: str) -> float:
        return -74.0060

    def timezone(self, ip: str) -> str:
        return "America/New_York"

    def asn(self, ip: str) -> tuple[int, str]:
        return (self._asn_value, self.asn_name)

    def is_datacenter(self, ip: str) -> bool:
        return self._dc

    def is_residential(self, ip: str) -> bool:
        return self._res

    def is_vpn(self, ip: str) -> bool:
        return self._vpn


class DatacenterGeoBackend(MockGeoBackend):
    """ASN-56880-like cloud range + datacenter heuristics."""

    def __init__(self):
        super().__init__(country="US", asn=13335, asn_name="Cloudflare", datacenter=True)


class ResidentialGeoBackend(MockGeoBackend):
    """ASN-32498-style ISP for test deterministic behaviour."""

    def __init__(self):
        super().__init__(country="BR", asn=32498, asn_name="Example ISP", residential=True)
