"""Subdomain takeover: DNS records that point at third-party resources nobody owns any more.

When a subdomain has a CNAME to e.g. ``myapp.herokuapp.com`` and that app is
deleted, anyone can register ``myapp`` on Heroku and serve content (phishing
pages, cookie-stealing scripts) from your domain.

How we look:

1. Collect subdomains from certificate transparency logs (crt.sh) plus a short
   list of common names.
2. Follow each one's CNAME chain.
3. If the final target belongs to a known service, either the service's own
   "nothing here" page confirms the resource is unclaimed, or (for services
   where that is enough) the target name no longer exists in DNS.
4. A CNAME to a name that does not exist at all, on any provider, is reported
   as a dangling record with lower confidence.

Everything is DNS lookups plus at most one homepage request for subdomains
that point at a known service, so this stays a passive check. Fingerprints are
based on the community-maintained "can-i-take-over-xyz" project and should be
re-checked against it periodically: services change their error pages.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Protocol

import httpx

from ..models import Category, Finding, Severity
from ..safety import UnsafeTargetError
from .base import ScanContext

log = logging.getLogger(__name__)

MAX_SUBDOMAINS = 60
CONCURRENCY = 20
MAX_CNAME_HOPS = 5

COMMON_NAMES = (
    "www", "mail", "blog", "shop", "store", "dev", "staging", "stage", "test", "api", "app", "docs", "help",
    "support", "status", "cdn", "assets", "static", "media", "beta", "demo", "portal", "admin", "news",
    "careers", "jobs", "go", "events", "community", "forum", "landing", "marketing", "promo", "old", "legacy",
)  # fmt: skip

_HOST = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass(frozen=True)
class Service:
    name: str
    cname_suffixes: tuple[str, ...]
    #: Text on the service's page when the resource behind the CNAME is unclaimed.
    fingerprints: tuple[str, ...] = ()
    #: The target vanishing from DNS (NXDOMAIN) means it can be re-registered.
    nxdomain_claimable: bool = False
    how_to_reclaim: str = ""


SERVICES: tuple[Service, ...] = (
    Service("GitHub Pages", ("github.io",), ("There isn't a GitHub Pages site here.",),
            how_to_reclaim="add the domain back to the repository's Pages settings"),
    Service("Heroku", ("herokuapp.com", "herokudns.com", "herokussl.com"), ("No such app",),
            how_to_reclaim="re-create the app and add the custom domain"),
    # Bucket hostnames vary by region and style; the S3-specific error code keeps the broad suffix safe.
    Service("Amazon S3", ("amazonaws.com",), ("NoSuchBucket",),
            how_to_reclaim="re-create the bucket with the same name in your account"),
    Service("AWS Elastic Beanstalk", ("elasticbeanstalk.com",), nxdomain_claimable=True,
            how_to_reclaim="re-create the environment with the same CNAME prefix"),
    Service("Microsoft Azure",
            ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net",
             "azure-api.net", "azurecontainer.io", "azureedge.net", "search.windows.net", "servicebus.windows.net"),
            nxdomain_claimable=True, how_to_reclaim="re-create the Azure resource with the same name"),
    Service("Shopify", ("myshopify.com",), ("Sorry, this shop is currently unavailable.",),
            how_to_reclaim="re-attach the domain in your Shopify admin"),
    Service("Fastly", ("fastly.net",), ("Fastly error: unknown domain",),
            how_to_reclaim="add the domain back to your Fastly service"),
    Service("Pantheon", ("pantheonsite.io",), ("The gods are wise, but do not know of the site which you seek.",),
            how_to_reclaim="add the domain back to the Pantheon site"),
    Service("Tumblr", ("domains.tumblr.com",),
            ("Whatever you were looking for doesn't currently exist at this address.",),
            how_to_reclaim="re-attach the domain to your Tumblr blog"),
    Service("Ghost", ("ghost.io",), ("Failed to resolve DNS path for this host",),
            how_to_reclaim="re-attach the domain to your Ghost(Pro) site"),
    Service("Surge.sh", ("surge.sh",), ("project not found",),
            how_to_reclaim="re-publish the project to the same domain"),
    Service("Bitbucket", ("bitbucket.io",), ("Repository not found",),
            how_to_reclaim="re-create the repository"),
    Service("ReadMe", ("readme.io",), ("Project doesnt exist... yet!",),
            how_to_reclaim="re-attach the domain to your ReadMe project"),
    Service("Help Scout", ("helpscoutdocs.com",), ("No settings were found for this company:",),
            how_to_reclaim="re-attach the domain to your Help Scout Docs site"),
    Service("Webflow", ("proxy.webflow.com", "proxy-ssl.webflow.com"),
            ("The page you are looking for doesn't exist or has been moved.",),
            how_to_reclaim="re-attach the domain to your Webflow project"),
    Service("Unbounce", ("unbouncepages.com",), ("The requested URL was not found on this server.",),
            how_to_reclaim="re-attach the domain in Unbounce"),
    Service("Strikingly", ("s.strikinglydns.com",), ("But if you're looking to build your own website",),
            how_to_reclaim="re-attach the domain to your Strikingly site"),
    Service("WordPress.com", ("wordpress.com",), ("Do you want to register",),
            how_to_reclaim="re-attach the domain to your WordPress.com site"),
)  # fmt: skip


def service_for(cname: str) -> Service | None:
    for svc in SERVICES:
        if any(cname == s or cname.endswith("." + s) for s in svc.cname_suffixes):
            return svc
    return None


class SubdomainSource(Protocol):
    async def subdomains(self, domain: str) -> list[str]: ...


class CrtShSource:
    """Subdomains seen in public certificate transparency logs (crt.sh, free, no key)."""

    URL = "https://crt.sh/"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self.client = client or httpx.AsyncClient(timeout=25.0)

    async def subdomains(self, domain: str) -> list[str]:
        resp = await self.client.get(self.URL, params={"q": f"%.{domain}", "output": "json"})
        resp.raise_for_status()
        return parse_crtsh(resp.text, domain)


def parse_crtsh(text: str, domain: str) -> list[str]:
    names: set[str] = set()
    for entry in json.loads(text or "[]"):
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().removeprefix("*.").rstrip(".")
            if name != domain and name.endswith("." + domain) and _HOST.match(name):
                names.add(name)
    return sorted(names)


def _clean(record: str) -> str:
    return record.strip().rstrip(".").lower()


@dataclass(frozen=True)
class Candidate:
    subdomain: str
    chain: list[str]  # CNAME targets in order; last one is where the name finally points

    @property
    def target(self) -> str:
        return self.chain[-1]


class SubdomainTakeoverCheck:
    name = "subdomain_takeover"
    title = "Subdomain takeover (dangling DNS records)"
    active = False

    def __init__(self, source: SubdomainSource | None = None) -> None:
        self.source = source or CrtShSource()

    async def run(self, ctx: ScanContext) -> list[Finding]:
        domain = ctx.target.registrable_hint
        out: list[Finding] = []

        names = {f"{label}.{domain}" for label in COMMON_NAMES}
        try:
            names.update(await self.source.subdomains(domain))
        except (httpx.HTTPError, ValueError) as exc:
            log.info("certificate transparency lookup failed for %s: %s", domain, exc)
            out.append(
                Finding(
                    id="subdomains.ct_unavailable",
                    title="Only common subdomain names were checked",
                    severity=Severity.INFO,
                    category=Category.SUBDOMAINS,
                    description=(
                        "The certificate transparency log service did not answer, so subdomains with unusual "
                        "names were not checked. Re-run the scan later for full coverage."
                    ),
                )
            )
        # Certificate-transparency names first (they really exist), then common guesses, capped.
        ordered = sorted(names, key=lambda n: (n.split(".", 1)[0] in COMMON_NAMES, n))[:MAX_SUBDOMAINS]

        sem = asyncio.Semaphore(CONCURRENCY)

        async def examine(sub: str) -> Finding | None:
            async with sem:
                candidate = await self._cname_chain(ctx, sub)
                if candidate is None:
                    return None
                return await self._judge(ctx, candidate)

        results = await asyncio.gather(*(examine(n) for n in ordered))
        out.extend(f for f in results if f is not None)
        return out

    async def _cname_chain(self, ctx: ScanContext, sub: str) -> Candidate | None:
        chain: list[str] = []
        name = sub
        for _ in range(MAX_CNAME_HOPS):
            records = await ctx.dns(name, "CNAME")
            if not records:
                break
            name = _clean(records[0])
            if name in chain:
                break
            chain.append(name)
        return Candidate(sub, chain) if chain else None

    async def _judge(self, ctx: ScanContext, c: Candidate) -> Finding | None:
        svc = next((s for s in (service_for(t) for t in c.chain) if s), None)
        target_exists = await ctx.exists(c.target)
        evidence = f"{c.subdomain} CNAME " + " -> ".join(c.chain)

        if svc and svc.nxdomain_claimable and target_exists is False:
            return _takeover(c, svc, evidence + f"\n{c.target} does not exist (NXDOMAIN)")

        if svc and svc.fingerprints and target_exists is not False:
            body = await self._homepage(ctx, c.subdomain)
            hit = next((fp for fp in svc.fingerprints if body is not None and fp in body), None)
            if hit:
                return _takeover(c, svc, evidence + f'\nThe page says: "{hit}"')

        if target_exists is False:
            return Finding(
                id=f"subdomains.dangling.{c.subdomain}",
                title=f"{c.subdomain} points to a name that doesn't exist",
                severity=Severity.MEDIUM if svc is None else Severity.HIGH,
                category=Category.SUBDOMAINS,
                description=(
                    "This DNS record is left over from something that was removed. If the target domain or "
                    "resource can be registered again, whoever does so controls this subdomain."
                ),
                evidence=evidence + f"\n{c.target} does not exist (NXDOMAIN)",
                fix=f"Delete the CNAME record for {c.subdomain} unless you still need it.",
                snippets={"DNS": f"Remove: {c.subdomain}. CNAME {c.chain[0]}."},
            )
        return None

    @staticmethod
    async def _homepage(ctx: ScanContext, host: str) -> str | None:
        for scheme in ("https", "http"):
            try:
                res = await ctx.fetcher.get(f"{scheme}://{host}/")
            except (httpx.HTTPError, UnsafeTargetError, OSError):
                continue
            return res.text[:200_000]
        return None


def _takeover(c: Candidate, svc: Service, evidence: str) -> Finding:
    return Finding(
        id=f"subdomains.takeover.{c.subdomain}",
        title=f"{c.subdomain} can likely be taken over ({svc.name})",
        severity=Severity.HIGH,
        category=Category.SUBDOMAINS,
        description=(
            f"{c.subdomain} still points at {svc.name}, but nothing is set up there any more. Anyone who signs "
            f"up for {svc.name} can claim it and publish content under your domain: phishing pages, fake login "
            "forms, or scripts that read cookies shared across your subdomains."
        ),
        evidence=evidence,
        fix=(
            f"Delete the DNS record for {c.subdomain} now if you no longer use it. If you do still need it, "
            f"{svc.how_to_reclaim or 're-claim the resource on ' + svc.name} before someone else does."
        ),
        snippets={"DNS": f"Remove: {c.subdomain}. CNAME {c.chain[0]}."},
        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
    )
