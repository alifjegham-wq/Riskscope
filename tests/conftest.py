from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from riskscope.appscan.osv import Package, Vuln
from riskscope.checks.base import ScanContext
from riskscope.models import Severity
from riskscope.safety import SafeFetcher, parse_target

PUBLIC_IP = "93.184.216.34"

Handler = Callable[[httpx.Request], httpx.Response]


async def public_resolver(host: str) -> list[str]:
    return ["10.0.0.5"] if host.startswith("internal.") else [PUBLIC_IP]


class FakeDns:
    """Records keyed by (name, type). `missing` names answer NXDOMAIN; `unknown` ones time out."""

    def __init__(
        self,
        records: dict[tuple[str, str], list[str]] | None = None,
        missing: set[str] | None = None,
        unknown: set[str] | None = None,
    ) -> None:
        self.records = records or {}
        self.missing = missing or set()
        self.unknown = unknown or set()

    async def __call__(self, name: str, rdtype: str) -> list[str]:
        return self.records.get((name, rdtype), [])

    async def exists(self, name: str) -> bool | None:
        if name in self.unknown:
            return None
        return name not in self.missing


class FakeVulns:
    def __init__(self, db: dict[tuple[str, str], list[Vuln]] | None = None) -> None:
        self.db = db or {}
        self.queried: list[Package] = []

    async def lookup(self, packages: list[Package]) -> dict[Package, list[Vuln]]:
        self.queried.extend(packages)
        return {p: self.db[(p.name, p.version)] for p in packages if (p.name, p.version) in self.db}


def site(routes: dict[str, httpx.Response], default: httpx.Response | None = None) -> Handler:
    """Route on 'scheme://host/path' or just '/path'."""

    def handler(request: httpx.Request) -> httpx.Response:
        full = f"{request.url.scheme}://{request.url.host}{request.url.path}"
        for key in (full, request.url.path):
            if key in routes:
                return routes[key]
        return default or httpx.Response(404, text="<html>not found</html>")

    return handler


def make_ctx(
    handler: Handler, dns: FakeDns | None = None, host: str = "example.com", verified: bool = False
) -> ScanContext:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    dns = dns or FakeDns()
    return ScanContext(
        target=parse_target(host),
        fetcher=SafeFetcher(client, public_resolver),
        dns=dns,
        exists=dns.exists,
        verified_owner=verified,
    )


@pytest.fixture
def jquery_vuln() -> Vuln:
    return Vuln(
        id="GHSA-xxxx",
        summary="XSS in jQuery.htmlPrefilter",
        severity=Severity.MEDIUM,
        fixed=["3.5.0"],
        aliases=["CVE-2020-11022"],
    )
