import httpx
import pytest
from fastapi.testclient import TestClient

from riskscope.checks.headers import SecurityHeadersCheck
from riskscope.checks.ports import OpenPortsCheck
from riskscope.config import Settings
from riskscope.verification import DNS_LABEL, token_for
from riskscope.web.app import create_app

from .conftest import FakeDns, FakeVulns, public_resolver, site

SECRET = "test-secret"


async def _all_open(ip: str, port: int) -> bool:
    return port == 6379


def make_client(dns: FakeDns | None = None, limit: int = 100) -> TestClient:
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(site({"/": httpx.Response(200, text="hi")})))
    app = create_app(
        Settings(verify_secret=SECRET, scans_per_hour=limit),
        http=upstream,
        vulns=FakeVulns(),
        resolver=public_resolver,
        dns=dns or FakeDns(),
        checks=[SecurityHeadersCheck(), OpenPortsCheck(_all_open)],
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
