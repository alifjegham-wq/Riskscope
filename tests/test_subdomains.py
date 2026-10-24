import json

import httpx
import pytest

from riskscope.checks.subdomains import (
    COMMON_NAMES,
    MAX_SUBDOMAINS,
    CrtShSource,
    SubdomainTakeoverCheck,
    parse_crtsh,
    service_for,
)
from riskscope.models import Finding, Severity

from .conftest import FakeDns, make_ctx, site


class FakeSource:
    def __init__(self, names: list[str] | None = None, fail: bool = False) -> None:
        self.names = names or []
        self.fail = fail

    async def subdomains(self, domain: str) -> list[str]:
        if self.fail:
            raise httpx.ConnectTimeout("crt.sh down")
        return self.names


def by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def test_service_matching_is_by_domain_suffix() -> None:
    assert service_for("acme.github.io") is not None
    assert service_for("acme.herokuapp.com") is not None
    assert service_for("files.s3.eu-west-1.amazonaws.com") is not None
    assert service_for("notgithub.io") is None  # suffix must start at a label boundary
    assert service_for("github.io.evil.com") is None


def test_parse_crtsh() -> None:
    data = [
        {"name_value": "example.com\n*.example.com"},
        {"name_value": "Shop.Example.com\nwww.example.com"},
        {"name_value": "evil.com\nexample.com.evil.com\nbad_name.example.com"},
    ]
    assert parse_crtsh(json.dumps(data), "example.com") == ["shop.example.com", "www.example.com"]


async def test_crtsh_source_queries_wildcard() -> None:
    seen: list[httpx.URL] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url)
        return httpx.Response(200, json=[{"name_value": "a.example.com"}])

    src = CrtShSource(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert await src.subdomains("example.com") == ["a.example.com"]
    assert seen[0].params["q"] == "%.example.com"


async def test_github_pages_fingerprint_is_high() -> None:
    dns = FakeDns({("docs.example.com", "CNAME"): ["acme.github.io."]})
    routes = {"https://docs.example.com/": httpx.Response(404, text="<h1>There isn't a GitHub Pages site here.</h1>")}
    found = by_id(await SubdomainTakeoverCheck(FakeSource(["docs.example.com"])).run(make_ctx(site(routes), dns)))
    f = found["subdomains.takeover.docs.example.com"]
    assert f.severity is Severity.HIGH and "GitHub Pages" in f.title
    assert "acme.github.io" in f.evidence and "There isn't a GitHub Pages site here." in f.evidence
    assert "docs.example.com" in f.snippets["DNS"]


async def test_claimed_github_pages_site_is_fine() -> None:
    dns = FakeDns({("docs.example.com", "CNAME"): ["acme.github.io."]})
    routes = {"https://docs.example.com/": httpx.Response(200, text="<h1>Our docs</h1>")}
    assert await SubdomainTakeoverCheck(FakeSource(["docs.example.com"])).run(make_ctx(site(routes), dns)) == []


async def test_azure_nxdomain_is_takeover() -> None:
    dns = FakeDns(
        {("app.example.com", "CNAME"): ["acme-prod.azurewebsites.net."]}, missing={"acme-prod.azurewebsites.net"}
    )
    found = by_id(await SubdomainTakeoverCheck(FakeSource(["app.example.com"])).run(make_ctx(site({}), dns)))
    f = found["subdomains.takeover.app.example.com"]
    assert "Microsoft Azure" in f.title and "NXDOMAIN" in f.evidence


async def test_azure_dns_timeout_is_not_reported() -> None:
    dns = FakeDns(
        {("app.example.com", "CNAME"): ["acme-prod.azurewebsites.net."]}, unknown={"acme-prod.azurewebsites.net"}
    )
    assert await SubdomainTakeoverCheck(FakeSource(["app.example.com"])).run(make_ctx(site({}), dns)) == []


async def test_generic_dangling_cname_follows_chain() -> None:
    dns = FakeDns(
        {
            ("promo.example.com", "CNAME"): ["promo.agency-cdn.net."],
            ("promo.agency-cdn.net", "CNAME"): ["edge.expired-agency.com."],
        },
        missing={"edge.expired-agency.com"},
    )
    found = by_id(await SubdomainTakeoverCheck(FakeSource(["promo.example.com"])).run(make_ctx(site({}), dns)))
    f = found["subdomains.dangling.promo.example.com"]
    assert f.severity is Severity.MEDIUM
    assert "promo.agency-cdn.net -> edge.expired-agency.com" in f.evidence


async def test_cname_loop_terminates() -> None:
    dns = FakeDns({("a.example.com", "CNAME"): ["b.example.com."], ("b.example.com", "CNAME"): ["a.example.com."]})
    assert await SubdomainTakeoverCheck(FakeSource(["a.example.com"])).run(make_ctx(site({}), dns)) == []


async def test_ct_failure_falls_back_to_common_names() -> None:
    dns = FakeDns({("shop.example.com", "CNAME"): ["acme.myshopify.com."]})
    routes = {"https://shop.example.com/": httpx.Response(200, text="Sorry, this shop is currently unavailable.")}
    found = by_id(await SubdomainTakeoverCheck(FakeSource(fail=True)).run(make_ctx(site(routes), dns)))
    assert found["subdomains.ct_unavailable"].severity is Severity.INFO
    assert "subdomains.takeover.shop.example.com" in found


async def test_www_target_enumerates_parent_domain_and_caps_work() -> None:
    queried: list[str] = []

    class CountingDns(FakeDns):
        async def __call__(self, name: str, rdtype: str) -> list[str]:
            queried.append(name)
            return []

    many = [f"host{i}.example.com" for i in range(200)]
    await SubdomainTakeoverCheck(FakeSource(many)).run(make_ctx(site({}), CountingDns(), host="www.example.com"))
    assert len(queried) == MAX_SUBDOMAINS
    assert all(q.endswith(".example.com") for q in queried)
    assert queried.count("host0.example.com") == 1  # CT names are checked before common guesses


async def test_redirect_to_private_ip_is_not_followed() -> None:
    dns = FakeDns({("docs.example.com", "CNAME"): ["acme.github.io."]})
    routes = {"https://docs.example.com/": httpx.Response(302, headers={"location": "http://169.254.169.254/"})}
    # The unsafe redirect is refused; with no page to read there is no finding (and no crash).
    assert await SubdomainTakeoverCheck(FakeSource(["docs.example.com"])).run(make_ctx(site(routes), dns)) == []


@pytest.mark.parametrize("label", ["www", "blog", "staging"])
def test_common_names_present(label: str) -> None:
    assert label in COMMON_NAMES
