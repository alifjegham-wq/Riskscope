"""Guard rails for a scanner that fetches URLs on behalf of the public.

A hosted scanner is an SSRF machine unless every outbound request is checked:
targets must be public hostnames, every address they resolve to must be a
public unicast address, and redirects are followed by hand so each hop is
re-validated. DNS rebinding between our check and httpx's own resolution is
still possible, so deployments must also block private ranges at the network
layer (see README, "Deploying").
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

Resolver = Callable[[str], Awaitable[list[str]]]

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 2_000_000
USER_AGENT = "riskscope/0.1 (+https://github.com/alifjegham-wq/Riskscope; free security scanner)"

_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


class UnsafeTargetError(ValueError):
    """The target is not something we are willing to scan."""


@dataclass(frozen=True)
class Target:
    host: str
    url: str  # normalised https:// URL of the site root

    @property
    def registrable_hint(self) -> str:
        """Best-effort parent domain for DNS/email checks (www.example.com -> example.com)."""
        return self.host[4:] if self.host.startswith("www.") else self.host


def parse_target(raw: str) -> Target:
    raw = raw.strip()
    if not raw:
        raise UnsafeTargetError("Enter a website address, e.g. example.com")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise UnsafeTargetError("Only http and https websites can be scanned")
    if parts.username or parts.password:
        raise UnsafeTargetError("Addresses with embedded credentials are not accepted")
    host = (parts.hostname or "").rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UnsafeTargetError("That does not look like a valid domain name") from exc
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise UnsafeTargetError("Scan a domain name rather than an IP address")
    if not _HOSTNAME.match(host) or host.endswith((".local", ".internal", ".localhost", ".lan", ".home.arpa")):
        raise UnsafeTargetError("That does not look like a public domain name")
    if parts.port not in (None, 80, 443):
        raise UnsafeTargetError("Only the standard web ports (80/443) can be scanned")
    return Target(host=host, url=f"https://{host}/")


def is_public_ip(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def system_resolver(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


async def assert_public_host(host: str, resolver: Resolver) -> list[str]:
    try:
        addrs = await resolver(host)
    except OSError as exc:
        raise UnsafeTargetError(f"Could not resolve {host}") from exc
    if not addrs:
        raise UnsafeTargetError(f"{host} has no addresses")
    bad = [a for a in addrs if not is_public_ip(a)]
    if bad:
        raise UnsafeTargetError(f"{host} resolves to a non-public address; refusing to scan it")
    return addrs


@dataclass
class FetchResult:
    response: httpx.Response
    body: bytes
    history: list[str]  # URLs visited, first to last

    @property
    def text(self) -> str:
        return self.body.decode(self.response.encoding or "utf-8", errors="replace")


class SafeFetcher:
    """httpx wrapper that validates every hop and caps body size."""

    def __init__(self, client: httpx.AsyncClient, resolver: Resolver = system_resolver) -> None:
        self.client = client
        self.resolver = resolver
        self._validated: set[str] = set()

    async def _check(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise UnsafeTargetError(f"Refusing to follow a redirect to {parts.scheme}:")
        if parts.port not in (None, 80, 443):
            raise UnsafeTargetError("Refusing to follow a redirect to a non-standard port")
        host = (parts.hostname or "").lower()
        if host not in self._validated:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                await assert_public_host(host, self.resolver)
            else:
                if not is_public_ip(host):
                    raise UnsafeTargetError("Refusing to follow a redirect to a private address")
            self._validated.add(host)

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None, follow_redirects: bool = True
    ) -> FetchResult:
        history: list[str] = []
        for _ in range(MAX_REDIRECTS + 1):
            await self._check(url)
            history.append(url)
            req_headers = {"User-Agent": USER_AGENT, **(headers or {})}
            async with self.client.stream("GET", url, headers=req_headers, follow_redirects=False) as resp:
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body.extend(chunk)
                    if len(body) >= MAX_BODY_BYTES:
                        break
            if follow_redirects and resp.is_redirect and "location" in resp.headers:
                url = urljoin(url, resp.headers["location"])
                continue
            return FetchResult(response=resp, body=bytes(body[:MAX_BODY_BYTES]), history=history)
        raise UnsafeTargetError("Too many redirects")

    async def options(self, url: str) -> httpx.Response:
        """A single OPTIONS request (validated, no redirects). Used to read the advertised methods."""
        await self._check(url)
        return await self.client.request("OPTIONS", url, headers={"User-Agent": USER_AGENT}, follow_redirects=False)
