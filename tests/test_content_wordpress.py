import httpx

from riskscope.checks.content import MixedContentCheck
from riskscope.checks.wordpress import WordPressCheck, is_wordpress
from riskscope.models import Finding, Severity

from .conftest import make_ctx, site


def ids(findings: list[Finding]) -> set[str]:
    return {f.id for f in findings}


# ---- mixed content ---------------------------------------------------------


async def test_mixed_content_active_and_passive() -> None:
    html = (
        '<script src="http://cdn.example/x.js"></script>'
        '<link rel="stylesheet" href="http://cdn.example/x.css">'
        '<img src="http://cdn.example/i.png">'
    )
    found = ids(await MixedContentCheck().run(make_ctx(site({"/": httpx.Response(200, text=html)}))))
    assert found == {"content.mixed.active", "content.mixed.passive"}


async def test_mixed_content_clean_https_page() -> None:
    html = '<script src="https://cdn.example/x.js"></script><img src="/local.png">'
    assert await MixedContentCheck().run(make_ctx(site({"/": httpx.Response(200, text=html)}))) == []


async def test_mixed_content_only_active() -> None:
    html = '<iframe src="http://widget.example/"></iframe>'
    [f] = await MixedContentCheck().run(make_ctx(site({"/": httpx.Response(200, text=html)})))
    assert f.id == "content.mixed.active" and f.severity is Severity.MEDIUM


# ---- WordPress -------------------------------------------------------------


def test_is_wordpress() -> None:
    assert is_wordpress('<link href="/wp-content/themes/x/style.css">')
    assert is_wordpress('<meta name="generator" content="WordPress 6.3">')
    assert not is_wordpress("<html>a plain site</html>")


async def test_wordpress_exposures() -> None:
    routes = {
        "/": httpx.Response(200, text='<link href="/wp-content/themes/t/style.css">'),
        "/readme.html": httpx.Response(200, content=b"<h1>WordPress</h1>\nVersion 6.3.1\n"),
        "/wp-json/wp/v2/users": httpx.Response(200, content=b'[{"id":1,"slug":"admin","name":"Admin"}]'),
        "/xmlrpc.php": httpx.Response(200, content=b"XML-RPC server accepts POST requests only."),
    }
    found = {f.id: f for f in await WordPressCheck().run(make_ctx(site(routes)))}
    assert set(found) == {
        "wordpress.version_disclosure",
        "wordpress.user_enumeration",
        "wordpress.xmlrpc_enabled",
    }
    assert "6.3.1" in found["wordpress.version_disclosure"].title
    assert "admin" in found["wordpress.user_enumeration"].evidence
    assert found["wordpress.user_enumeration"].severity is Severity.MEDIUM


async def test_not_wordpress_is_skipped() -> None:
    assert await WordPressCheck().run(make_ctx(site({"/": httpx.Response(200, text="<html>plain</html>")}))) == []
