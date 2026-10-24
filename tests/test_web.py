import re

import httpx
import pytest
from fastapi.testclient import TestClient

from riskscope.checks.headers import SecurityHeadersCheck
from riskscope.checks.ports import OpenPortsCheck
from riskscope.config import Settings
from riskscope.notify import Email, LogMailer
from riskscope.verification import DNS_LABEL, token_for
from riskscope.web.app import create_app

from .conftest import FakeDns, FakeVulns, public_resolver, site

SECRET = "test-secret"


async def _all_open(ip: str, port: int) -> bool:
    return port == 6379


def make_client(dns: FakeDns | None = None, limit: int = 100, mailer: LogMailer | None = None) -> TestClient:
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(site({"/": httpx.Response(200, text="hi")})))
    app = create_app(
        Settings(
            verify_secret=SECRET,
            scans_per_hour=limit,
            database_path=":memory:",
            scheduler_enabled=False,
            public_base_url="https://riskscope.test",
        ),
        http=upstream,
        vulns=FakeVulns(),
        resolver=public_resolver,
        dns=dns or FakeDns(),
        checks=[SecurityHeadersCheck(), OpenPortsCheck(_all_open)],
        mailer=mailer or LogMailer(),
    )
    return TestClient(app)


def test_index_has_strict_security_headers() -> None:
    with make_client() as c:
        r = c.get("/")
        assert r.status_code == 200 and "Scan a website" in r.text
        assert "default-src 'none'" in r.headers["content-security-policy"]
        assert r.headers["x-frame-options"] == "DENY"


def test_passive_scan_report_page() -> None:
    with make_client() as c:
        r = c.post("/scan", data={"target": "example.com"})
        assert r.status_code == 200
        assert "No Content-Security-Policy" in r.text and "passive checks only" in r.text
        assert "Redis" not in r.text  # active check skipped


def test_private_target_rejected() -> None:
    with make_client() as c:
        r = c.post("/scan", data={"target": "internal.example.com"})
        assert r.status_code == 400 and "non-public" in r.text


def test_deep_scan_requires_verification_then_runs() -> None:
    with make_client() as c:
        r = c.post("/scan", data={"target": "example.com", "deep": "true"})
        assert "Prove you own" in r.text and token_for("example.com", SECRET) in r.text

    dns = FakeDns({(f"{DNS_LABEL}.example.com", "TXT"): [token_for("example.com", SECRET)]})
    with make_client(dns) as c:
        r = c.post("/scan", data={"target": "example.com", "deep": "true"})
        assert "owner verified" in r.text and "Redis (port 6379)" in r.text


def test_api_scan_json_and_forbidden_deep() -> None:
    with make_client() as c:
        body = c.get("/api/scan", params={"target": "example.com"}).json()
        assert body["kind"] == "website" and body["grade"] in "ABCDF" and body["findings"]
        assert c.get("/api/scan", params={"target": "example.com", "deep": True}).status_code == 403
        assert c.get("/api/scan", params={"target": "127.0.0.1"}).status_code == 400


def test_code_upload() -> None:
    with make_client() as c:
        r = c.post("/code", files=[("files", ("settings.py", b'K="AKIAIOSFODNN7EXAMPLE"', "text/plain"))])
        assert r.status_code == 200 and "AWS access key committed in settings.py" in r.text
        assert "AKIAIOSFODNN7EXAMPLE" not in r.text


def test_rate_limit() -> None:
    with make_client(limit=1) as c:
        assert c.get("/api/scan", params={"target": "example.com"}).status_code == 200
        assert c.get("/api/scan", params={"target": "example.com"}).status_code == 429


@pytest.mark.parametrize("path", ["/how-it-works", "/verify?target=example.com", "/healthz"])
def test_pages_render(path: str) -> None:
    with make_client() as c:
        assert c.get(path).status_code == 200


def _verified_dns() -> FakeDns:
    return FakeDns({(f"{DNS_LABEL}.example.com", "TXT"): [token_for("example.com", SECRET)]})


def test_share_flow_create_view_delete() -> None:
    with make_client() as c:
        r = c.post("/scan", data={"target": "example.com", "share": "true"})
        assert "Shareable link" in r.text
        share = re.search(r"https://riskscope\.test(/r/[\w-]+)<", r.text)
        delete = re.search(r'href="https://riskscope\.test(/r/[\w-]+/delete/[\w-]+)"', r.text)
        assert share and delete

        view = c.get(share.group(1))
        assert view.status_code == 200 and "Shared report" in view.text and "No Content-Security-Policy" in view.text
        assert view.headers["x-robots-tag"].startswith("noindex") and "no-store" in view.headers["cache-control"]
        assert "/delete/" not in view.text  # the delete link is only shown to the creator

        assert c.get(share.group(1) + "/delete/wrong").status_code == 404
        assert c.post(share.group(1) + "/delete/wrong").status_code == 404
        assert c.get(delete.group(1)).status_code == 200
        assert c.post(delete.group(1)).status_code == 200
        assert c.get(share.group(1)).status_code == 404


def test_unshared_scans_are_not_stored() -> None:
    with make_client() as c:
        c.post("/scan", data={"target": "example.com"})
        store = c.app.state.services.store  # type: ignore[attr-defined]
        assert store._db.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 0


def test_api_share() -> None:
    with make_client() as c:
        body = c.get("/api/scan", params={"target": "example.com", "share": True}).json()
        rid = body["share_url"].rsplit("/", 1)[1]
        again = c.get(f"/api/reports/{rid}").json()
        assert again["grade"] == body["grade"] and again["share_url"] is None
        assert c.get("/api/reports/missing").status_code == 404


def test_monitor_requires_verification_and_valid_email() -> None:
    mailer = LogMailer()
    with make_client(mailer=mailer) as c:
        r = c.post("/monitor", data={"target": "example.com", "email": "me@example.com"})
        assert r.status_code == 400 and "verification token" in r.text
    with make_client(_verified_dns(), mailer=mailer) as c:
        r = c.post("/monitor", data={"target": "example.com", "email": "not-an-email"})
        assert r.status_code == 400 and "valid email" in r.text
    assert mailer.sent == []


def test_monitor_full_lifecycle() -> None:
    mailer = LogMailer()
    with make_client(_verified_dns(), mailer=mailer) as c:
        assert "Monitor example.com" in c.get("/monitor", params={"target": "example.com"}).text
        r = c.post("/monitor", data={"target": "example.com", "email": "me@example.com", "frequency": "daily"})
        assert "Check your inbox" in r.text
        [confirm] = mailer.sent
        manage = re.search(r"https://riskscope\.test(/m/[\w-]+/[\w-]+)", confirm.body)
        assert manage
        path = manage.group(1)

        page = c.get(path)
        assert "isn't switched on yet" in page.text and page.headers["x-robots-tag"].startswith("noindex")
        assert c.get(path[:-2] + "xx").status_code == 404  # wrong token

        # Opening the link alone must not activate (mail scanners prefetch links).
        scheduler = c.app.state.scheduler  # type: ignore[attr-defined]
        assert c.portal is not None
        assert c.portal.call(scheduler.tick) == 0
        assert c.post(path + "/activate", follow_redirects=False).status_code == 303
        assert c.portal.call(scheduler.tick) == 1
        assert "Monitoring example.com" in mailer.sent[-1].subject

        page = c.get(path)
        assert "re-scanned <strong>daily</strong>" in page.text and "History" in page.text
        c.post(path + "/frequency", data={"frequency": "weekly"})
        assert "re-scanned <strong>weekly</strong>" in c.get(path).text

        # Asking again for the same site sends a manage link instead of creating a duplicate.
        c.post("/monitor", data={"target": "example.com", "email": "ME@example.com"})
        assert "already monitored" in mailer.sent[-1].body

        assert "Monitoring stopped" in c.post(path + "/unsubscribe").text
        assert c.get(path).status_code == 404


def test_monitor_limit_per_email() -> None:
    dns = FakeDns({(f"{DNS_LABEL}.site{i}.com", "TXT"): [token_for(f"site{i}.com", SECRET)] for i in range(7)})
    with make_client(dns) as c:
        for i in range(5):
            assert c.post("/monitor", data={"target": f"site{i}.com", "email": "a@b.co"}).status_code == 200
        r = c.post("/monitor", data={"target": "site6.com", "email": "a@b.co"})
        assert r.status_code == 400 and "at most 5" in r.text


class _BrokenMailer(LogMailer):
    async def send(self, email: Email) -> None:
        raise OSError("smtp down")


def test_monitor_mail_failure_is_a_friendly_error() -> None:
    with make_client(_verified_dns(), mailer=_BrokenMailer()) as c:
        r = c.post("/monitor", data={"target": "example.com", "email": "me@example.com"})
        assert r.status_code == 503 and "send the email just now" in r.text


def test_monitor_digest_opt_in_and_toggle() -> None:
    mailer = LogMailer()
    with make_client(_verified_dns(), mailer=mailer) as c:
        assert 'name="digest"' in c.get("/monitor", params={"target": "example.com"}).text
        c.post("/monitor", data={"target": "example.com", "email": "me@example.com", "digest": "true"})
        manage = re.search(r"https://riskscope\.test(/m/[\w-]+/[\w-]+)", mailer.sent[0].body)
        assert manage
        path = manage.group(1)
        c.post(path + "/activate")
        page = c.get(path).text
        assert "Weekly summary: <strong>on</strong>" in page and "next around" in page

        assert c.post(path + "/digest", follow_redirects=False).status_code == 303  # no field = turn off
        assert "Weekly summary: <strong>off</strong>" in c.get(path).text
        c.post(path + "/digest", data={"enabled": "true"})
        assert "Weekly summary: <strong>on</strong>" in c.get(path).text
        assert c.post(path[:-2] + "xx/digest", data={"enabled": "true"}).status_code == 404


def test_public_server_without_smtp_hides_monitoring() -> None:
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(site({"/": httpx.Response(200, text="hi")})))
    app = create_app(
        Settings(
            verify_secret=SECRET,
            database_path=":memory:",
            scheduler_enabled=False,
            public_base_url="https://riskscope.onrender.com",
        ),
        http=upstream,
        vulns=FakeVulns(),
        resolver=public_resolver,
        dns=_verified_dns(),
        checks=[SecurityHeadersCheck()],
    )
    with TestClient(app) as c:
        assert "Keep watching your site" not in c.get("/").text
        assert "Set up monitoring" not in c.post("/scan", data={"target": "example.com"}).text
        assert c.get("/monitor", params={"target": "example.com"}).status_code == 503
        r = c.post("/monitor", data={"target": "example.com", "email": "me@example.com"})
        assert r.status_code == 503 and "no email set up" in r.text
        assert '<link rel="stylesheet" href="/static/style.css">' in c.get("/").text


def test_local_server_keeps_monitoring_with_logged_email() -> None:
    with make_client() as c:  # injected mailer counts as configured
        assert "Keep watching your site" in c.get("/").text


def _client(settings: Settings, mailer: LogMailer | None = None) -> TestClient:
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(site({"/": httpx.Response(200, text="hi")})))
    return TestClient(
        create_app(
            settings,
            http=upstream,
            vulns=FakeVulns(),
            resolver=public_resolver,
            dns=_verified_dns(),
            checks=[SecurityHeadersCheck()],
            mailer=mailer,
        )
    )


def test_ephemeral_storage_hides_sharing_and_monitoring() -> None:
    settings = Settings(
        verify_secret=SECRET,
        database_path=":memory:",
        scheduler_enabled=False,
        persistent_storage=False,
        smtp_host="smtp.example.org",
    )
    with _client(settings, LogMailer()) as c:
        home = c.get("/").text
        assert 'name="share"' not in home and "Keep watching your site" not in home
        r = c.post("/scan", data={"target": "example.com", "share": "true"})
        assert r.status_code == 200 and "Shareable link" not in r.text and "Set up monitoring" not in r.text
        assert c.get("/api/scan", params={"target": "example.com", "share": True}).status_code == 503
        assert c.get("/api/scan", params={"target": "example.com"}).status_code == 200
        assert c.get("/monitor", params={"target": "example.com"}).status_code == 503
        store = c.app.state.services.store  # type: ignore[attr-defined]
        assert store._db.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 0


def test_installable_app_assets() -> None:
    with make_client() as c:
        home = c.get("/")
        assert '<link rel="manifest" href="/manifest.webmanifest">' in home.text
        assert '<script src="/static/app.js" defer></script>' in home.text
        csp = home.headers["content-security-policy"]
        for directive in ("script-src 'self'", "manifest-src 'self'", "worker-src 'self'", "connect-src 'self'"):
            assert directive in csp
        assert "unsafe-inline" not in csp

        m = c.get("/manifest.webmanifest")
        assert m.headers["content-type"].startswith("application/manifest+json")
        manifest = m.json()
        assert manifest["display"] == "standalone" and manifest["start_url"] == "/"
        for icon in manifest["icons"]:
            assert c.get(icon["src"]).status_code == 200
        assert any(i.get("purpose") == "maskable" for i in manifest["icons"])

        sw = c.get("/sw.js")
        assert sw.status_code == 200 and sw.headers["content-type"].startswith("text/javascript")
        assert "caches" in sw.text and sw.headers["cache-control"] == "no-cache"
        assert "You're offline" in c.get("/offline").text.replace("&#39;", "'")
        assert c.get("/static/apple-touch-icon.png").status_code == 200
