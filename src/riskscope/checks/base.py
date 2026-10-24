"""Shared plumbing for website checks."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..models import Finding
from ..safety import FetchResult, SafeFetcher, Target

DnsLookup = Callable[[str, str], Awaitable[list[str]]]


async def system_dns(name: str, rdtype: str) -> list[str]:
    """Return record data as text; empty list when the name or type does not exist."""
    try:
        answer = await dns.asyncresolver.resolve(name, rdtype, lifetime=5.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return []
    out: list[str] = []
    for rdata in answer:
        if rdtype == "TXT":
            out.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
        else:
            out.append(rdata.to_text())
    return out


@dataclass
class ScanContext:
    target: Target
    fetcher: SafeFetcher
    dns: DnsLookup = system_dns
    verified_owner: bool = False
    _homepage: FetchResult | None = field(default=None, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    async def homepage(self) -> FetchResult:
        """The site root over HTTPS, fetched once and shared by every check."""
        async with self._lock:
            if self._homepage is None:
                self._homepage = await self.fetcher.get(self.target.url)
            return self._homepage


class Check(Protocol):
    name: str
    title: str
    #: Active checks touch more than a normal visitor would and need verified ownership.
    active: bool

    async def run(self, ctx: ScanContext) -> list[Finding]: ...
