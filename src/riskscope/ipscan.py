"""Scan by IP address or CIDR block: find the site(s) hosted there, then scan each.

Given an IP, or a small CIDR block, riskscope discovers the hostnames served on
each address three ways and runs the normal passive website checks on each one it
finds:

1. **Reverse DNS (PTR)** — the address's PTR record.
2. **TLS certificate** — the subject and SubjectAltName hostnames on the cert
   presented on port 443 (no third party involved).
3. **Passive DNS** — an optional provider that lists domains seen pointing at the
   address. Off unless one is configured, because it sends the IP to that service.

Safety:

* Only public, globally-routable addresses are accepted; private, loopback,
  link-local (incl. cloud metadata) and reserved ranges are refused, and a block
  larger than ``max_hosts`` addresses is rejected.
* Every discovered hostname is **forward-confirmed** — it must itself resolve to a
  public address — before it is scanned, so a crafted PTR or certificate can't
  redirect the scanner at an internal host.
* Only passive checks run on discovered sites. Active port checks still require
  per-domain ownership verification, which scanning a block does not provide.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from .checks.base import DnsLookup
from .safety import Resolver, UnsafeTargetError, assert_public_host, is_public_ip, parse_target

#: Largest block we will enumerate (a /24, or a /120 for IPv6). Keeps one request bounded.
MAX_HOSTS = 256
#: Most distinct sites we will actually scan from one IP/CIDR request.
MAX_SITES = 10
CERT_TIMEOUT = 6.0

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
CertProbe = Callable[[str], list[str]]


@dataclass(frozen=True)
class IpTarget:
    raw: str
    network: Network

    @property
    def is_single(self) -> bool:
        return self.network.num_addresses == 1

    @property
    def label(self) -> str:
        return str(self.network.network_address) if self.is_single else str(self.network)

    def addresses(self) -> list[str]:
        if self.is_single:
            return [str(self.network.network_address)]
        return [str(h) for h in self.network.hosts()]


def looks_like_ip_target(raw: str) -> bool:
    raw = raw.strip()
    try:
        if "/" in raw:
            ipaddress.ip_network(raw, strict=False)
        else:
            ipaddress.ip_address(raw)
    except ValueError:
        return False
    return True


def parse_ip_target(raw: str, max_hosts: int = MAX_HOSTS) -> IpTarget:
    raw = raw.strip()
    if not raw:
        raise UnsafeTargetError("Enter an IP address or CIDR block, e.g. 203.0.113.10 or 203.0.113.0/24")
    try:
        network: Network = (
            ipaddress.ip_network(raw, strict=False) if "/" in raw else ipaddress.ip_network(ipaddress.ip_address(raw))
        )
    except ValueError as exc:
        raise UnsafeTargetError("That is not a valid IP address or CIDR block") from exc
    if not network.is_global or network.is_multicast:
        raise UnsafeTargetError("Only public IP addresses can be scanned, not private or reserved ranges")
    if network.num_addresses > max_hosts:
        raise UnsafeTargetError(f"That block is too large; scan at most {max_hosts} addresses (for example a /24)")
    return IpTarget(raw=raw, network=network)


# ---- hostname discovery ----------------------------------------------------


class PassiveDnsSource(Protocol):
    async def hostnames(self, ip: str) -> list[str]: ...


class NullPassiveSource:
    """Default: no passive-DNS provider configured, so the IP is sent to no third party."""

    async def hostnames(self, ip: str) -> list[str]:
        return []


def cert_hostnames(ip: str, timeout: float = CERT_TIMEOUT) -> list[str]:
    """Hostnames on the TLS certificate served at ip:443 (blocking; validity is not checked)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((ip, 443), timeout=timeout)
    try:
        with ctx.wrap_socket(raw) as sock:  # no SNI: we want the default cert for the address
            der = sock.getpeercert(binary_form=True)
    finally:
        raw.close()
    if not der:
        return []
    cert = x509.load_der_x509_certificate(der)
    names: set[str] = set()
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        san = None
    if san is not None and isinstance(san.value, x509.SubjectAlternativeName):
        names.update(san.value.get_values_for_type(x509.DNSName))
    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        names.add(str(attr.value))
    return sorted({n.lower().removeprefix("*.") for n in names})


async def ptr_hostnames(ip: str, dns: DnsLookup) -> list[str]:
    try:
        reverse = ipaddress.ip_address(ip).reverse_pointer
    except ValueError:
        return []
    return [h.rstrip(".").lower() for h in await dns(reverse, "PTR") if h.strip(". ")]


@dataclass(frozen=True)
class DiscoveredSite:
    host: str
    #: Human-readable discovery methods that turned it up, e.g. ["reverse DNS", "TLS certificate"].
    sources: list[str]
    ip: str


@dataclass
class Discovery:
    target: IpTarget
    ips_probed: int = 0
    sites: list[DiscoveredSite] = field(default_factory=list)
    #: Addresses that answered nothing and messages about capped work.
    notes: list[str] = field(default_factory=list)


async def discover_sites(
    target: IpTarget,
    *,
    dns: DnsLookup,
    resolver: Resolver,
    passive: PassiveDnsSource,
    cert_probe: CertProbe = cert_hostnames,
    max_sites: int = MAX_SITES,
) -> Discovery:
    addresses = target.addresses()
    discovery = Discovery(target=target, ips_probed=len(addresses))
    # host -> (sources, first ip it was seen on). dicts keep discovery order stable.
    found: dict[str, tuple[set[str], str]] = {}

    def add(host: str, source: str, ip: str) -> None:
        host = host.strip().rstrip(".").lower().removeprefix("*.")
        if host:
            found.setdefault(host, (set(), ip))[0].add(source)

    for ip in addresses:
        for host in await ptr_hostnames(ip, dns):
            add(host, "reverse DNS", ip)
        try:
            cert_names = await asyncio.to_thread(cert_probe, ip)
        except OSError:
            cert_names = []
        for host in cert_names:
            add(host, "TLS certificate", ip)
        for host in await passive.hostnames(ip):
            add(host, "passive DNS", ip)

    for host, (sources, ip) in found.items():
        if len(discovery.sites) >= max_sites:
            discovery.notes.append(f"More than {max_sites} sites were found; only the first {max_sites} were scanned.")
            break
        try:
            parsed = parse_target(host)
            await assert_public_host(parsed.host, resolver)
        except UnsafeTargetError:
            continue  # not a public hostname, or no longer resolves to a public address
        discovery.sites.append(DiscoveredSite(host=parsed.host, sources=sorted(sources), ip=ip))
    return discovery


# ---- an optional passive-DNS provider --------------------------------------


class HackerTargetSource:
    """Reverse-IP lookup via hackertarget.com (free, rate-limited, no key).

    Enabled only when RISKSCOPE_REVERSE_IP_PROVIDER=hackertarget. It sends the
    scanned IP to hackertarget.com; see docs before turning it on for a public
    deployment.
    """

    URL = "https://api.hackertarget.com/reverseiplookup/"

    def __init__(self, client: object) -> None:  # httpx.AsyncClient, kept loose to avoid a hard import here
        self.client = client

    async def hostnames(self, ip: str) -> list[str]:
        resp = await self.client.get(self.URL, params={"q": ip})  # type: ignore[attr-defined]
        text = resp.text if resp.status_code == 200 else ""
        if not text or "error" in text.lower() or "no records" in text.lower():
            return []
        out = []
        for line in text.splitlines():
            line = line.strip().rstrip(".").lower()
            # The API sometimes returns "hostname / ip"; keep the hostname half only.
            host = line.split("/", 1)[0].strip().split()[0] if line else ""
            if host and not _is_ip(host):
                out.append(host)
        return sorted(set(out))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def passive_source(provider: str, client: object) -> PassiveDnsSource:
    if provider.strip().lower() == "hackertarget":
        return HackerTargetSource(client)
    return NullPassiveSource()


__all__ = [
    "MAX_HOSTS",
    "MAX_SITES",
    "DiscoveredSite",
    "Discovery",
    "IpTarget",
    "NullPassiveSource",
    "PassiveDnsSource",
    "cert_hostnames",
    "discover_sites",
    "is_public_ip",
    "looks_like_ip_target",
    "parse_ip_target",
    "passive_source",
]
