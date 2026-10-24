"""FastAPI web front end: HTML pages for people, JSON endpoints for scripts."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..appscan import UploadError, expand_upload, scan_code
from ..appscan.osv import OsvClient, VulnSource
from ..checks import Check, ScanContext, default_checks
from ..checks.base import DnsLookup, system_dns
from ..config import Settings
from ..models import Report, Severity
from ..safety import Resolver, SafeFetcher, Target, UnsafeTargetError, parse_target, system_resolver
from ..scanner import scan_website
from ..scoring import CRITICAL_CAP, GRADES, WEIGHTS
from ..verification import DNS_LABEL, WELL_KNOWN_PATH, is_verified, token_for
from .ratelimit import RateLimiter

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")

# Our own pages must pass our own scanner.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    ),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


@dataclass
class Services:
    settings: Settings
    http: httpx.AsyncClient
    vulns: VulnSource
    resolver: Resolver
    dns: DnsLookup
    checks: list[Check]
    limiter: RateLimiter


def create_app(
    settings: Settings | None = None,
    *,
    http: httpx.AsyncClient | None = None,
    vulns: VulnSource | None = None,
    resolver: Resolver = system_resolver,
    dns: DnsLookup = system_dns,
    checks: list[Check] | None = None,
) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        client = http or httpx.AsyncClient(timeout=settings.http_timeout_s, verify=True)
        vuln_source = vulns or OsvClient()
        app.state.services = Services(
            settings=settings,
            http=client,
            vulns=vuln_source,
            resolver=resolver,
            dns=dns,
            checks=checks if checks is not None else default_checks(vuln_source),
            limiter=RateLimiter(settings.scans_per_hour),
        )
        yield
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

    async def run_site_scan(request: Request, raw_target: str, deep: bool) -> tuple[Target, Report | None, bool]:
        s = svc(request)
        target = parse_target(raw_target)
        fetcher = SafeFetcher(s.http, s.resolver)
        verified = False
        if deep:
            verified = await is_verified(target, s.settings.verify_secret, s.dns, fetcher)
            if not verified:
                return target, None, False
        ctx = ScanContext(target=target, fetcher=fetcher, dns=s.dns, verified_owner=verified)
        return target, await scan_website(ctx, s.checks), verified

    def page(request: Request, name: str, status: int = 200, **ctx: object) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            name,
            {"Severity": Severity, **ctx},
            status_code=status,
        )

    # ---- HTML -------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return page(request, "index.html", max_upload_mb=svc(request).settings.max_upload_mb)

    @app.get("/how-it-works", response_class=HTMLResponse)
    async def how(request: Request) -> HTMLResponse:
        return page(request, "how.html", weights=WEIGHTS, grades=GRADES, critical_cap=CRITICAL_CAP)

    @app.post("/scan", response_class=HTMLResponse)
    async def scan_page(
        request: Request, target: Annotated[str, Form()], deep: Annotated[bool, Form()] = False
    ) -> HTMLResponse:
        try:
            check_rate(request)
            parsed, report, _ = await run_site_scan(request, target, deep)
        except UnsafeTargetError as exc:
            return page(
                request,
                "index.html",
                400,
                error=str(exc),
                target=target,
                max_upload_mb=svc(request).settings.max_upload_mb,
            )
        except HTTPException as exc:
            return page(
                request,
                "index.html",
                exc.status_code,
                error=exc.detail,
                target=target,
                max_upload_mb=svc(request).settings.max_upload_mb,
            )
        if report is None:
            return verify_page(request, parsed, failed=True)
        return page(request, "report.html", report=report)

    def verify_page(request: Request, target: Target, failed: bool = False) -> HTMLResponse:
        token = token_for(target.registrable_hint, svc(request).settings.verify_secret)
        return page(
            request,
            "verify.html",
            target=target,
            token=token,
            dns_name=f"{DNS_LABEL}.{target.registrable_hint}",
            file_url=target.url + WELL_KNOWN_PATH,
            failed=failed,
        )

    @app.get("/verify", response_class=HTMLResponse)
    async def verify(request: Request, target: str) -> HTMLResponse:
        try:
            return verify_page(request, parse_target(target))
        except UnsafeTargetError as exc:
            return page(
                request,
                "index.html",
                400,
                error=str(exc),
                target=target,
                max_upload_mb=svc(request).settings.max_upload_mb,
            )

    @app.post("/code", response_class=HTMLResponse)
    async def code_page(request: Request, files: Annotated[list[UploadFile], File()]) -> HTMLResponse:
        try:
            check_rate(request)
            report = await _scan_uploads(request, files)
        except (UploadError, HTTPException) as exc:
            msg = exc.detail if isinstance(exc, HTTPException) else str(exc)
            status = exc.status_code if isinstance(exc, HTTPException) else 400
            return page(
                request,
                "index.html",
                status,
                code_error=msg,
                max_upload_mb=svc(request).settings.max_upload_mb,
            )
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

    # ---- JSON API -----------------------------------------------------------

    @app.get("/api/scan")
    async def api_scan(request: Request, target: str, deep: bool = False) -> Report:
        check_rate(request)
        try:
            parsed, report, _ = await run_site_scan(request, target, deep)
        except UnsafeTargetError as exc:
            raise HTTPException(400, str(exc)) from exc
        if report is None:
            token = token_for(parsed.registrable_hint, svc(request).settings.verify_secret)
            raise HTTPException(
                403,
                f"Ownership not verified. Publish TXT {DNS_LABEL}.{parsed.registrable_hint} = {token} "
                f"or serve it at {parsed.url + WELL_KNOWN_PATH}",
            )
        return report

    @app.post("/api/code")
    async def api_code(request: Request, files: Annotated[list[UploadFile], File()]) -> Report:
        check_rate(request)
        try:
            return await _scan_uploads(request, files)
        except UploadError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"ok": True})

    return app
