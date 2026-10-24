"""FastAPI web front end: HTML pages for people, JSON endpoints for scripts."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Annotated, TypedDict

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..appscan import UploadError, expand_upload, scan_code
from ..appscan.osv import OsvClient, VulnSource
from ..checks import Check, ScanContext, default_checks
from ..checks.base import DnsLookup, ExistsLookup, system_dns, system_exists
from ..config import Settings
from ..ipscan import (
    CertProbe,
    DiscoveredSite,
    Discovery,
    PassiveDnsSource,
    cert_hostnames,
    discover_sites,
    looks_like_ip_target,
    parse_ip_target,
    passive_source,
)
from ..models import Report, Severity
from ..monitoring import Scheduler, confirm_email
from ..notify import Email, LogMailer, Mailer, SmtpMailer
from ..safety import Resolver, SafeFetcher, Target, UnsafeTargetError, parse_target, system_resolver
from ..scanner import scan_website
from ..scoring import CRITICAL_CAP, GRADES, WEIGHTS
from ..store import Frequency, Monitor, Store, check_monitor_token, monitor_token
from ..verification import DNS_LABEL, WELL_KNOWN_PATH, is_verified, token_for
from .ratelimit import RateLimiter

log = logging.getLogger(__name__)
HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.filters["datetime"] = lambda ts: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))

# Our own pages must pass our own scanner.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "manifest-src 'self'; worker-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
# Shared reports and manage pages are reachable by link only: keep them out of search engines and caches.
PRIVATE_PAGE_HEADERS = {"X-Robots-Tag": "noindex, nofollow", "Cache-Control": "private, no-store"}
_PRIVATE_PREFIXES = ("/r/", "/m/", "/api/reports/")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")


@dataclass
class IpScanResult:
    discovery: Discovery
    scanned: list[tuple[DiscoveredSite, Report]]


class VerificationCtx(TypedDict):
    target: Target
    token: str
    dns_name: str
    file_url: str


@dataclass
class Services:
    settings: Settings
    http: httpx.AsyncClient
    vulns: VulnSource
    resolver: Resolver
    dns: DnsLookup
    exists: ExistsLookup
    checks: list[Check]
    limiter: RateLimiter
    store: Store
    mailer: Mailer
    passive: PassiveDnsSource
    cert_probe: CertProbe = cert_hostnames
    #: Monitoring needs working email. On a public server without SMTP the sign-up is hidden, because
    #: confirmation emails would only reach the server log. Locally the log is how you follow the links.
    monitoring_enabled: bool = True
    #: Shareable links need storage that survives restarts.
    sharing_enabled: bool = True

    @property
    def base_url(self) -> str:
        return self.settings.public_base_url.rstrip("/")

    def manage_url(self, monitor: Monitor) -> str:
        return f"{self.base_url}/m/{monitor.id}/{monitor_token(self.settings.verify_secret, monitor.id)}"

    async def verified(self, target: Target) -> bool:
        return await is_verified(target, self.settings.verify_secret, self.dns, SafeFetcher(self.http, self.resolver))

    async def scan(self, target: Target, want_active: bool) -> Report:
        """Website scan; active checks run only if asked for and ownership verifies right now."""
        fetcher = SafeFetcher(self.http, self.resolver)
        verified = want_active and await is_verified(target, self.settings.verify_secret, self.dns, fetcher)
        ctx = ScanContext(target=target, fetcher=fetcher, dns=self.dns, exists=self.exists, verified_owner=verified)
        return await scan_website(ctx, self.checks)

    async def ip_scan(self, raw: str) -> IpScanResult:
        """Find the site(s) hosted on an IP or CIDR block and scan each (passive checks only)."""
        target = parse_ip_target(raw, self.settings.max_cidr_hosts)
        discovery = await discover_sites(
            target,
            dns=self.dns,
            resolver=self.resolver,
            passive=self.passive,
            cert_probe=self.cert_probe,
            max_sites=self.settings.max_ip_sites,
        )
        scanned: list[tuple[DiscoveredSite, Report]] = []
        for site in discovery.sites:
            report = await self.scan(parse_target(site.host), False)
            scanned.append((site, report))
        return IpScanResult(discovery=discovery, scanned=scanned)

    async def share(self, report: Report) -> Report:
        ttl = self.settings.share_ttl_days * 86_400
        rid, token = await asyncio.to_thread(self.store.save_report, report, ttl)
        report.share_url = f"{self.base_url}/r/{rid}"
        report.delete_url = f"{self.base_url}/r/{rid}/delete/{token}"
        return report


def _mailer_for(settings: Settings) -> Mailer:
    if not settings.smtp_host:
        return LogMailer()
    return SmtpMailer(
        settings.smtp_host,
        settings.smtp_port,
        settings.smtp_from,
        settings.smtp_username,
        settings.smtp_password,
        settings.smtp_starttls,
    )


def create_app(
    settings: Settings | None = None,
    *,
    http: httpx.AsyncClient | None = None,
    vulns: VulnSource | None = None,
    resolver: Resolver = system_resolver,
    dns: DnsLookup = system_dns,
    exists: ExistsLookup = system_exists,
    checks: list[Check] | None = None,
    mailer: Mailer | None = None,
    passive: PassiveDnsSource | None = None,
    cert_probe: CertProbe = cert_hostnames,
) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        client = http or httpx.AsyncClient(timeout=settings.http_timeout_s, verify=True)
        vuln_source = vulns or OsvClient()
        store = Store(settings.database_path)
        mail = mailer or _mailer_for(settings)
        passive_src = passive if passive is not None else passive_source(settings.reverse_ip_provider, client)
        services = Services(
            settings=settings,
            http=client,
            vulns=vuln_source,
            resolver=resolver,
            dns=dns,
            exists=exists,
            checks=checks if checks is not None else default_checks(vuln_source),
            limiter=RateLimiter(settings.scans_per_hour),
            store=store,
            mailer=mail,
            passive=passive_src,
            cert_probe=cert_probe,
            monitoring_enabled=settings.persistent_storage
            and (bool(settings.smtp_host) or mailer is not None or settings.is_local),
            sharing_enabled=settings.persistent_storage,
        )
        scheduler = Scheduler(
            store=store,
            scan=services.scan,
            mailer=mail,
            base_url=services.base_url,
            report_ttl_s=settings.share_ttl_days * 86_400,
            manage_link=services.manage_url,
        )
        app.state.services = services
        app.state.scheduler = scheduler
        task = (
            asyncio.create_task(scheduler.run_forever(settings.scheduler_interval_s))
            if settings.scheduler_enabled
            else None
        )
        yield
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        store.close()
        if http is None:
            await client.aclose()

    app = FastAPI(title="riskscope", lifespan=lifespan, docs_url="/api/docs", redoc_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        if request.url.path != "/api/docs":  # Swagger UI needs inline scripts
            for k, v in SECURITY_HEADERS.items():
                response.headers.setdefault(k, v)
        if request.url.path.startswith(_PRIVATE_PREFIXES):
            response.headers.update(PRIVATE_PAGE_HEADERS)
        return response

    def svc(request: Request) -> Services:
        s: Services = request.app.state.services
        return s

    def client_ip(request: Request) -> str:
        if svc(request).settings.trust_proxy and "x-forwarded-for" in request.headers:
            return request.headers["x-forwarded-for"].split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def check_rate(request: Request) -> None:
        if not svc(request).limiter.allow(client_ip(request)):
            raise HTTPException(429, "Scan limit reached for this hour. Please try again later.")

    async def run_site_scan(request: Request, raw_target: str, deep: bool) -> tuple[Target, Report | None]:
        s = svc(request)
        target = parse_target(raw_target)
        if deep and not await s.verified(target):
            return target, None
        return target, await s.scan(target, deep)

    def page(request: Request, name: str, status: int = 200, **ctx: object) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            name,
            {
                "Severity": Severity,
                "max_upload_mb": svc(request).settings.max_upload_mb,
                "share_ttl_days": svc(request).settings.share_ttl_days,
                "monitoring_enabled": svc(request).monitoring_enabled,
                "sharing_enabled": svc(request).sharing_enabled,
                **ctx,
            },
            status_code=status,
        )

    def message(request: Request, title: str, text: str, status: int = 200) -> HTMLResponse:
        return page(request, "message.html", status, title=title, text=text)

    # ---- scanning (HTML) ---------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return page(request, "index.html")

    @app.get("/how-it-works", response_class=HTMLResponse)
    async def how(request: Request) -> HTMLResponse:
        return page(request, "how.html", weights=WEIGHTS, grades=GRADES, critical_cap=CRITICAL_CAP)

    @app.post("/scan", response_class=HTMLResponse)
    async def scan_page(
        request: Request,
        target: Annotated[str, Form()],
        deep: Annotated[bool, Form()] = False,
        share: Annotated[bool, Form()] = False,
    ) -> HTMLResponse:
        try:
            check_rate(request)
            if looks_like_ip_target(target):
                return page(request, "ip_scan.html", result=await svc(request).ip_scan(target))
            parsed, report = await run_site_scan(request, target, deep)
        except UnsafeTargetError as exc:
            return page(request, "index.html", 400, error=str(exc), target=target)
        except HTTPException as exc:
            return page(request, "index.html", exc.status_code, error=exc.detail, target=target)
        if report is None:
            return verify_page(request, parsed, failed=True)
        if share and svc(request).sharing_enabled:
            report = await svc(request).share(report)
        return page(request, "report.html", report=report)

    def verify_page(request: Request, target: Target, failed: bool = False) -> HTMLResponse:
        return page(request, "verify.html", failed=failed, **verification_ctx(request, target))

    def verification_ctx(request: Request, target: Target) -> VerificationCtx:
        return {
            "target": target,
            "token": token_for(target.registrable_hint, svc(request).settings.verify_secret),
            "dns_name": f"{DNS_LABEL}.{target.registrable_hint}",
            "file_url": target.url + WELL_KNOWN_PATH,
        }

    @app.get("/verify", response_class=HTMLResponse)
    async def verify(request: Request, target: str) -> HTMLResponse:
        try:
            return verify_page(request, parse_target(target))
        except UnsafeTargetError as exc:
            return page(request, "index.html", 400, error=str(exc), target=target)

    @app.post("/code", response_class=HTMLResponse)
    async def code_page(
        request: Request, files: Annotated[list[UploadFile], File()], share: Annotated[bool, Form()] = False
    ) -> HTMLResponse:
        try:
            check_rate(request)
            report = await _scan_uploads(request, files)
        except (UploadError, HTTPException) as exc:
            msg = exc.detail if isinstance(exc, HTTPException) else str(exc)
            status = exc.status_code if isinstance(exc, HTTPException) else 400
            return page(request, "index.html", status, code_error=msg)
        if share and svc(request).sharing_enabled:
            report = await svc(request).share(report)
        return page(request, "report.html", report=report)

    async def _scan_uploads(request: Request, files: list[UploadFile]) -> Report:
        s = svc(request)
        limit = s.settings.max_upload_mb * 1024 * 1024
        expanded: dict[str, bytes] = {}
        total = 0
        for f in files:
            data = await f.read(limit + 1)
            total += len(data)
            if total > limit:
                raise UploadError(f"Uploads are limited to {s.settings.max_upload_mb} MB")
            if f.filename:
                expanded.update(expand_upload(f.filename, data))
        if not expanded:
            raise UploadError("Choose at least one file or .zip to scan")
        label = files[0].filename if len(files) == 1 and files[0].filename else f"{len(expanded)} files"
        return await scan_code(expanded, s.vulns, label=label)

    # ---- shared reports ----------------------------------------------------

    @app.get("/r/{rid}", response_class=HTMLResponse)
    async def shared_report(request: Request, rid: str) -> HTMLResponse:
        stored = await asyncio.to_thread(svc(request).store.get_report, rid)
        if stored is None:
            return message(request, "Report not found", "This link is wrong, has expired, or was deleted.", 404)
        return page(request, "report.html", report=stored.report, shared=stored)

    @app.get("/r/{rid}/delete/{token}", response_class=HTMLResponse)
    async def delete_report_confirm(request: Request, rid: str, token: str) -> HTMLResponse:
        s = svc(request)
        if not await asyncio.to_thread(s.store.check_report_token, rid, token):
            return message(request, "Report not found", "This link is wrong, has expired, or was deleted.", 404)
        return page(request, "delete_report.html", rid=rid, token=token)

    @app.post("/r/{rid}/delete/{token}", response_class=HTMLResponse)
    async def delete_report(request: Request, rid: str, token: str) -> HTMLResponse:
        s = svc(request)
        if not await asyncio.to_thread(s.store.check_report_token, rid, token):
            return message(request, "Report not found", "This link is wrong, has expired, or was deleted.", 404)
        await asyncio.to_thread(s.store.delete_report, rid)
        return message(request, "Report deleted", "The shared link no longer works.")

    # ---- monitoring --------------------------------------------------------

    def monitoring_off(request: Request) -> HTMLResponse:
        return message(
            request,
            "Monitoring isn't available here yet",
            "This server has no email set up, so it can't send monitoring alerts. One-off scans work as usual.",
            503,
        )

    @app.get("/monitor", response_class=HTMLResponse)
    async def monitor_form(request: Request, target: str) -> HTMLResponse:
        if not svc(request).monitoring_enabled:
            return monitoring_off(request)
        try:
            parsed = parse_target(target)
        except UnsafeTargetError as exc:
            return page(request, "index.html", 400, error=str(exc), target=target)
        return page(request, "monitor_new.html", frequencies=list(Frequency), **verification_ctx(request, parsed))

    @app.post("/monitor", response_class=HTMLResponse)
    async def monitor_create(
        request: Request,
        target: Annotated[str, Form()],
        email: Annotated[str, Form()],
        frequency: Annotated[Frequency, Form()] = Frequency.WEEKLY,
        digest: Annotated[bool, Form()] = False,
    ) -> HTMLResponse:
        s = svc(request)
        if not s.monitoring_enabled:
            return monitoring_off(request)
        email = email.strip()
        try:
            parsed = parse_target(target)
        except UnsafeTargetError as exc:
            return page(request, "index.html", 400, error=str(exc), target=target)

        def again(error: str, status: int = 400) -> HTMLResponse:
            return page(
                request,
                "monitor_new.html",
                status,
                error=error,
                email=email,
                frequency=frequency,
                digest=digest,
                frequencies=list(Frequency),
                **verification_ctx(request, parsed),
            )

        try:
            check_rate(request)
        except HTTPException as exc:
            return again(str(exc.detail), exc.status_code)
        if not _EMAIL.match(email):
            return again("Enter a valid email address.")
        if not await s.verified(parsed):
            return again(
                "We couldn't find the verification token yet. Add the DNS record or file below, then try again "
                "(DNS changes can take a few minutes)."
            )

        existing = await asyncio.to_thread(s.store.find_monitor, parsed.host, email)
        if existing is None:
            if await asyncio.to_thread(s.store.count_monitors_for_email, email) >= s.settings.max_monitors_per_email:
                return again(f"An email address can monitor at most {s.settings.max_monitors_per_email} sites.")
            existing = await asyncio.to_thread(
                partial(s.store.create_monitor, parsed.host, email, frequency, digest=digest)
            )
        # Same reply whether or not the monitor already existed, so this form can't probe who monitors what.
        if existing.confirmed:
            mail = Email(
                existing.email,
                f"[riskscope] Manage monitoring for {existing.target}",
                f"{existing.target} is already monitored ({existing.frequency.value}).\n\n"
                f"Manage or stop it here: {s.manage_url(existing)}\n",
            )
        else:
            mail = confirm_email(existing, s.manage_url(existing))
        try:
            await s.mailer.send(mail)
        except Exception:  # noqa: BLE001 - SMTP trouble should read as a retryable error, not a crash
            log.exception("could not send monitor email")
            return again("We couldn't send the email just now. Please try again in a few minutes.", 503)
        return message(
            request,
            "Check your inbox",
            f'We sent a link to {email}. Open it and press "Activate" to start monitoring {parsed.host}.',
        )

    async def monitor_or_404(request: Request, mid: str, token: str) -> Monitor | None:
        s = svc(request)
        if not check_monitor_token(s.settings.verify_secret, mid, token):
            return None
        return await asyncio.to_thread(s.store.get_monitor, mid)

    def gone(request: Request) -> HTMLResponse:
        return message(request, "Monitor not found", "This link is wrong, or monitoring was already stopped.", 404)

    @app.get("/m/{mid}/{token}", response_class=HTMLResponse)
    async def monitor_manage(request: Request, mid: str, token: str) -> HTMLResponse:
        monitor = await monitor_or_404(request, mid, token)
        if monitor is None:
            return gone(request)
        history = await asyncio.to_thread(svc(request).store.history, mid)
        return page(
            request,
            "monitor_manage.html",
            monitor=monitor,
            token=token,
            history=history,
            frequencies=list(Frequency),
        )

    @app.post("/m/{mid}/{token}/activate", response_model=None)
    async def monitor_activate(request: Request, mid: str, token: str) -> Response:
        monitor = await monitor_or_404(request, mid, token)
        if monitor is None:
            return gone(request)
        if not monitor.confirmed:
            await asyncio.to_thread(svc(request).store.confirm_monitor, mid)
        return RedirectResponse(f"/m/{mid}/{token}", status_code=303)

    @app.post("/m/{mid}/{token}/frequency", response_model=None)
    async def monitor_frequency(
        request: Request, mid: str, token: str, frequency: Annotated[Frequency, Form()]
    ) -> Response:
        monitor = await monitor_or_404(request, mid, token)
        if monitor is None:
            return gone(request)
        await asyncio.to_thread(svc(request).store.set_frequency, mid, frequency)
        return RedirectResponse(f"/m/{mid}/{token}", status_code=303)

    @app.post("/m/{mid}/{token}/digest", response_model=None)
    async def monitor_digest(
        request: Request, mid: str, token: str, enabled: Annotated[bool, Form()] = False
    ) -> Response:
        monitor = await monitor_or_404(request, mid, token)
        if monitor is None:
            return gone(request)
        await asyncio.to_thread(svc(request).store.set_digest, mid, enabled)
        return RedirectResponse(f"/m/{mid}/{token}", status_code=303)

    @app.post("/m/{mid}/{token}/unsubscribe", response_class=HTMLResponse)
    async def monitor_stop(request: Request, mid: str, token: str) -> HTMLResponse:
        """Also the RFC 8058 one-click unsubscribe target, so it accepts a bare POST."""
        monitor = await monitor_or_404(request, mid, token)
        if monitor is None:
            return gone(request)
        await asyncio.to_thread(svc(request).store.delete_monitor, mid)
        return message(
            request,
            "Monitoring stopped",
            f"We won't scan {monitor.target} or email you about it again. Its scan history has been deleted.",
        )

    # ---- JSON API ------------------------------------------------------------

    async def share_or_plain(request: Request, report: Report, share: bool) -> Report:
        if not share:
            return report
        if not svc(request).sharing_enabled:
            raise HTTPException(503, "Shareable links are disabled on this server (no persistent storage)")
        return await svc(request).share(report)

    @app.get("/api/scan")
    async def api_scan(request: Request, target: str, deep: bool = False, share: bool = False) -> Report:
        check_rate(request)
        if looks_like_ip_target(target):
            raise HTTPException(400, "This looks like an IP address or CIDR block; use /api/ip-scan instead")
        try:
            parsed, report = await run_site_scan(request, target, deep)
        except UnsafeTargetError as exc:
            raise HTTPException(400, str(exc)) from exc
        if report is None:
            token = token_for(parsed.registrable_hint, svc(request).settings.verify_secret)
            raise HTTPException(
                403,
                f"Ownership not verified. Publish TXT {DNS_LABEL}.{parsed.registrable_hint} = {token} "
                f"or serve it at {parsed.url + WELL_KNOWN_PATH}",
            )
        return await share_or_plain(request, report, share)

    @app.post("/api/code")
    async def api_code(
        request: Request, files: Annotated[list[UploadFile], File()], share: Annotated[bool, Form()] = False
    ) -> Report:
        check_rate(request)
        try:
            report = await _scan_uploads(request, files)
        except UploadError as exc:
            raise HTTPException(400, str(exc)) from exc
        return await share_or_plain(request, report, share)

    @app.get("/api/ip-scan")
    async def api_ip_scan(request: Request, target: str) -> JSONResponse:
        check_rate(request)
        try:
            result = await svc(request).ip_scan(target)
        except UnsafeTargetError as exc:
            raise HTTPException(400, str(exc)) from exc
        return JSONResponse(
            {
                "target": result.discovery.target.label,
                "ips_probed": result.discovery.ips_probed,
                "notes": result.discovery.notes,
                "sites": [
                    {
                        "host": site.host,
                        "found_via": site.sources,
                        "ip": site.ip,
                        "report": report.model_dump(mode="json"),
                    }
                    for site, report in result.scanned
                ],
            }
        )

    @app.get("/api/reports/{rid}")
    async def api_report(request: Request, rid: str) -> Report:
        stored = await asyncio.to_thread(svc(request).store.get_report, rid)
        if stored is None:
            raise HTTPException(404, "Report not found or expired")
        return stored.report

    # ---- installable app (PWA) -----------------------------------------------

    @app.get("/manifest.webmanifest", include_in_schema=False)
    async def manifest() -> JSONResponse:
        return JSONResponse(
            {
                "name": "riskscope: free security scanner",
                "short_name": "riskscope",
                "description": "Scan websites and code for security risks and get a prioritised list of fixes.",
                "start_url": "/",
                "scope": "/",
                "display": "standalone",
                "background_color": "#f6f7f9",
                "theme_color": "#2457d6",
                "icons": [
                    {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png"},
                    {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png"},
                    {
                        "src": "/static/icon-maskable-512.png",
                        "sizes": "512x512",
                        "type": "image/png",
                        "purpose": "maskable",
                    },
                    {"src": "/static/icon.svg", "sizes": "any", "type": "image/svg+xml"},
                ],
            },
            media_type="application/manifest+json",
        )

    @app.get("/sw.js", include_in_schema=False)
    async def service_worker() -> FileResponse:
        # Served from the root so the worker's scope covers the whole site.
        return FileResponse(
            HERE / "static" / "sw.js", media_type="text/javascript", headers={"Cache-Control": "no-cache"}
        )

    @app.get("/offline", response_class=HTMLResponse, include_in_schema=False)
    async def offline(request: Request) -> HTMLResponse:
        return page(request, "offline.html")

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"ok": True})

    return app
