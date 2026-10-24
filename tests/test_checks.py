import time

import httpx

from riskscope.appscan.osv import Vuln
from riskscope.checks.cookies import CookieCheck
from riskscope.checks.dns_email import DnsHardeningCheck, EmailAuthCheck
from riskscope.checks.exposure import ExposedFilesCheck, SecurityTxtCheck
from riskscope.checks.headers import CORS_PROBE_ORIGIN, CorsCheck, HttpsRedirectCheck, SecurityHeadersCheck
from riskscope.checks.libraries import JsLibraryCheck, detect_libraries
from riskscope.checks.ports import OpenPortsCheck
from riskscope.checks.tls import TlsCheck, TlsInfo
from riskscope.models import Finding, Severity

from .conftest import FakeDns, FakeVulns, make_ctx, site

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
}


def ids(findings: list[Finding]) -> set[str]:
    return {f.id for f in findings}


async def test_well_configured_site_has_no_header_findings() -> None:
    ctx = make_ctx(site({"/": httpx.Response(200, headers=GOOD_HEADERS, text="<html></html>")}))
    assert await SecurityHeadersCheck().run(ctx) == []


async def test_bare_site_reports_missing_headers_and_versions() -> None:
    ctx = make_ctx(site({"/": httpx.Response(200, headers={"server": "Apache/2.4.29 (Ubuntu)"}, text="hi")}))
    found = ids(await SecurityHeadersCheck().run(ctx))
    assert {
        "headers.hsts.missing",
        "headers.csp.missing",
        "headers.framing.missing",
        "headers.nosniff.missing",
        "headers.referrer.missing",
        "headers.version_disclosure",
    } <= found


async def test_weak_hsts_and_unsafe_inline_csp() -> None:
    h = {
        **GOOD_HEADERS,
        "strict-transport-security": "max-age=600",
        "content-security-policy": "script-src 'self' 'unsafe-inline'; frame-ancestors 'self'",
    }
    ctx = make_ctx(site({"/": httpx.Response(200, headers=h)}))
    assert ids(await SecurityHeadersCheck().run(ctx)) == {"headers.hsts.short", "headers.csp.unsafe_inline"}


async def test_http_redirect() -> None:
    ok = make_ctx(
        site(
            {
                "http://example.com/": httpx.Response(301, headers={"location": "https://example.com/"}),
                "https://example.com/": httpx.Response(200),
            }
        )
    )
    assert await HttpsRedirectCheck().run(ok) == []
    bad = make_ctx(site({"/": httpx.Response(200, text="plain")}))
    assert ids(await HttpsRedirectCheck().run(bad)) == {"https.no_redirect"}


async def test_cors_reflection_with_credentials_is_high() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "access-control-allow-origin": req.headers.get("origin", ""),
                "access-control-allow-credentials": "true",
            },
        )

    [finding] = await CorsCheck().run(make_ctx(handler))
    assert finding.severity is Severity.HIGH and CORS_PROBE_ORIGIN in finding.evidence


async def test_cookie_flags() -> None:
    resp = httpx.Response(
        200,
        headers=[
            ("set-cookie", "sessionid=abc; Path=/"),
            ("set-cookie", "pref=1; Secure; HttpOnly; SameSite=Lax"),
        ],
    )
    [finding] = await CookieCheck().run(make_ctx(site({"/": resp})))
    assert finding.id == "cookies.flags.sessionid" and finding.severity is Severity.MEDIUM
    assert "abc" not in finding.evidence  # cookie values are never echoed


async def test_email_auth_missing_and_ok() -> None:
    missing = await EmailAuthCheck().run(make_ctx(site({}), FakeDns()))
    assert ids(missing) == {"email.spf.missing", "email.dmarc.missing"}
    good = FakeDns(
        {
            ("example.com", "TXT"): ["v=spf1 include:_spf.google.com -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
        }
    )
    assert await EmailAuthCheck().run(make_ctx(site({}), good)) == []


async def test_email_auth_weak_policies() -> None:
    dns = FakeDns({("example.com", "TXT"): ["v=spf1 +all"], ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"]})
    assert ids(await EmailAuthCheck().run(make_ctx(site({}), dns))) == {
        "email.spf.permissive",
        "email.dmarc.monitor_only",
    }


async def test_www_host_checks_parent_domain_dns() -> None:
    dns = FakeDns({("example.com", "CAA"): ['0 issue "letsencrypt.org"'], ("example.com", "DS"): ["1 2 3 abc"]})
    assert await DnsHardeningCheck().run(make_ctx(site({}), dns, host="www.example.com")) == []


async def test_exposed_git_and_env_detected() -> None:
    routes = {
        "/.git/HEAD": httpx.Response(200, text="ref: refs/heads/main\n"),
        "/.env": httpx.Response(200, text="DB_HOST=db\nDB_PASSWORD=hunter2\n"),
        "/": httpx.Response(200, text="<html>home</html>"),
    }
    found = await ExposedFilesCheck().run(make_ctx(site(routes)))
    assert {"exposure..git.HEAD", "exposure..env"} <= ids(found)
    assert all(f.severity is Severity.CRITICAL for f in found)


async def test_soft_404_site_has_no_false_positives() -> None:
    ctx = make_ctx(site({}, default=httpx.Response(200, text="<html><body>Welcome!</body></html>")))
    assert await ExposedFilesCheck().run(ctx) == []


async def test_directory_listing() -> None:
    ctx = make_ctx(site({"/": httpx.Response(200, text="<html><title>Index of /</title>")}))
    assert ids(await ExposedFilesCheck().run(ctx)) == {"exposure.directory_listing"}


async def test_security_txt() -> None:
    ok = make_ctx(site({"/.well-known/security.txt": httpx.Response(200, text="Contact: mailto:a@b.c\n")}))
    assert await SecurityTxtCheck().run(ok) == []
    assert ids(await SecurityTxtCheck().run(make_ctx(site({})))) == {"disclosure.security_txt.missing"}


def test_detect_libraries() -> None:
    html = """<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.15/lodash.min.js"></script>
    <script src="/js/app-2.0.0.js"></script>"""
    assert detect_libraries(html) == [("bootstrap", "4.3.1"), ("jquery", "1.12.4"), ("lodash", "4.17.15")]


async def test_js_library_check_reports_vulns(jquery_vuln: Vuln) -> None:
    html = '<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>'
    vulns = FakeVulns({("jquery", "3.4.1"): [jquery_vuln]})
    [f] = await JsLibraryCheck(vulns).run(make_ctx(site({"/": httpx.Response(200, text=html)})))
    assert f.title.startswith("jquery 3.4.1") and "3.5.0" in f.fix and "CVE-2020-11022" in f.evidence


async def test_tls_findings() -> None:
    soon = time.time() + 5 * 86400
    check = TlsCheck(probe=lambda host, ip: TlsInfo(protocol="TLSv1.3", not_after=soon, legacy_protocols=["TLS 1.0"]))
    found = await check.run(make_ctx(site({})))
    by_id = {f.id: f for f in found}
    assert by_id["tls.cert.expiry"].severity is Severity.HIGH and "tls.legacy_protocols" in by_id

    healthy = TlsCheck(probe=lambda host, ip: TlsInfo(protocol="TLSv1.3", not_after=time.time() + 90 * 86400))
    assert await healthy.run(make_ctx(site({}))) == []


async def test_tls_unreachable() -> None:
    def boom(host: str, ip: str) -> TlsInfo:
        raise ConnectionRefusedError("refused")

    assert ids(await TlsCheck(probe=boom).run(make_ctx(site({})))) == {"tls.unreachable"}


async def test_open_ports() -> None:
    async def connect(ip: str, port: int) -> bool:
        return port in (443, 6379, 3389)

    found = await OpenPortsCheck(connect).run(make_ctx(site({})))
    assert ids(found) == {"ports.6379", "ports.3389"}
