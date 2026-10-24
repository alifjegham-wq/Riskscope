import httpx
from fastapi.testclient import TestClient

from riskscope.checks.headers import SecurityHeadersCheck
from riskscope.config import Settings
from riskscope.notify import LogMailer
from riskscope.verification import DNS_LABEL, token_for
from riskscope.web.app import create_app

from .conftest import FakeDns, FakeVulns, public_resolver, site

SECRET = "bulk-secret"


def client(verified_domains: list[str], max_bulk: int = 25) -> TestClient:
    records = {(f"{DNS_LABEL}.{d}", "TXT"): [token_for(d, SECRET)] for d in verified_domains}
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(site({"/": httpx.Response(200, text="hi")})))
    app = create_app(
        Settings(verify_secret=SECRET, database_path=":memory:", scheduler_enabled=False, max_bulk_targets=max_bulk),
        http=upstream,
        vulns=FakeVulns(),
        resolver=public_resolver,
        dns=FakeDns(records),
        checks=[SecurityHeadersCheck()],
        mailer=LogMailer(),
    )
    return TestClient(app)


def test_bulk_page_scans_verified_and_gates_unverified() -> None:
    with client(["mine.com"]) as c:
        r = c.post("/bulk", data={"targets": "mine.com\nother.com\nnot a domain"})
        assert r.status_code == 200
        # mine.com is verified -> scanned with a grade and active checks noted
        assert "mine.com" in r.text and "active checks included" in r.text
        assert "No Content-Security-Policy" in r.text
        # other.com is unverified -> shown with its verification token, not scanned
        assert "other.com — not verified yet" in r.text
        assert token_for("other.com", SECRET) in r.text
        # junk is skipped with an error
        assert "skipped" in r.text


def test_bulk_requires_a_target() -> None:
    with client([]) as c:
        assert c.post("/bulk", data={"targets": "   "}).status_code == 400


def test_bulk_dedupes_and_caps() -> None:
    with client([f"d{i}.com" for i in range(30)], max_bulk=3) as c:
        many = "\n".join([f"d{i}.com" for i in range(30)] + ["d0.com"])  # includes a duplicate
        body = c.post("/api/bulk-scan", data={"targets": many.split("\n")}).json()
        assert len(body["items"]) == 3  # capped
        hosts = [i["host"] for i in body["items"]]
        assert len(hosts) == len(set(hosts))  # deduped


def test_api_bulk_scan_shape() -> None:
    with client(["mine.com"]) as c:
        body = c.post("/api/bulk-scan", data={"targets": ["mine.com", "other.com"]}).json()
        assert body["scanned"] == 1 and body["unverified"] == 1
        by_host = {i["host"]: i for i in body["items"]}
        assert by_host["mine.com"]["verified"] and by_host["mine.com"]["report"]["grade"] in "ABCDF"
        assert not by_host["other.com"]["verified"]
        assert by_host["other.com"]["verify"]["token"] == token_for("other.com", SECRET)
        assert by_host["other.com"]["report"] is None


def test_bulk_form_linked_from_home() -> None:
    with client([]) as c:
        assert 'href="/bulk"' in c.get("/").text
        assert "Scan several of your assets" in c.get("/bulk").text


def test_bulk_profile_narrows_checks() -> None:
    with client(["mine.com"]) as c:
        # 'email' excludes security_headers (the only registered check), so it does not run.
        narrowed = c.post("/bulk", data={"targets": "mine.com", "profile": "email"})
        assert narrowed.status_code == 200 and "No Content-Security-Policy" not in narrowed.text
        full = c.post("/bulk", data={"targets": "mine.com", "profile": "full"})
        assert "No Content-Security-Policy" in full.text


def test_bulk_offers_export() -> None:
    with client(["mine.com"]) as c:
        r = c.post("/bulk", data={"targets": "mine.com"})
        assert 'id="scan-export"' in r.text
        assert 'data-export="csv"' in r.text and 'data-export="json"' in r.text
        assert '"grade"' in r.text  # export rows are serialized into the page


def test_export_rows_shape() -> None:
    from riskscope.models import Report
    from riskscope.web.app import BulkItem, _export_rows

    rows = _export_rows(
        [
            BulkItem(
                target="mine.com", host="mine.com", verified=True, report=Report(target="mine.com", kind="website")
            ),
            BulkItem(target="other.com", host="other.com", token="t"),
            BulkItem(target="junk", error="bad"),
            BulkItem(
                target="203.0.113.0/24",
                host="found.example.com",
                report=Report(target="x", kind="website"),
                via="found on 203.0.113.0/24",
            ),
        ]
    )
    assert [r["status"] for r in rows] == ["scanned", "unverified", "error", "scanned"]
    assert rows[0]["grade"] == "A" and rows[0]["score"] == 100
    assert rows[3]["note"] == "found on 203.0.113.0/24"
    assert rows[2]["note"] == "bad"
