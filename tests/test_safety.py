import httpx
import pytest

from riskscope.safety import SafeFetcher, UnsafeTargetError, is_public_ip, parse_target

from .conftest import public_resolver


@pytest.mark.parametrize(
    ("raw", "host"),
    [
        ("example.com", "example.com"),
        ("https://Example.COM/path?q=1", "example.com"),
        ("http://www.example.com:443", "www.example.com"),
        ("bücher.de", "xn--bcher-kva.de"),
    ],
)
def test_parse_target_normalises(raw: str, host: str) -> None:
    t = parse_target(raw)
    assert t.host == host and t.url == f"https://{host}/"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "127.0.0.1",
        "http://[::1]/",
        "localhost",
        "printer.local",
        "ftp://example.com",
        "https://u:p@example.com",
        "example.com:8443",
        "metadata.google.internal",
        "-bad-.com",
    ],
)
def test_parse_target_rejects(raw: str) -> None:
    with pytest.raises(UnsafeTargetError):
        parse_target(raw)


@pytest.mark.parametrize(
    ("ip", "ok"),
    [
        ("8.8.8.8", True),
        ("10.1.2.3", False),
        ("169.254.169.254", False),
        ("127.0.0.1", False),
        ("::1", False),
        ("::ffff:10.0.0.1", False),
        ("100.64.0.1", False),
        ("2606:4700::1111", True),
        ("224.0.0.1", False),
    ],
)
def test_is_public_ip(ip: str, ok: bool) -> None:
    assert is_public_ip(ip) is ok


async def test_redirect_to_private_host_is_refused() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://internal.example.com/admin"})

    fetcher = SafeFetcher(httpx.AsyncClient(transport=httpx.MockTransport(handler)), public_resolver)
    with pytest.raises(UnsafeTargetError):
        await fetcher.get("https://example.com/")


async def test_redirect_to_metadata_ip_is_refused() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers={"location": "http://169.254.169.254/latest/meta-data/"})

    fetcher = SafeFetcher(httpx.AsyncClient(transport=httpx.MockTransport(handler)), public_resolver)
    with pytest.raises(UnsafeTargetError):
        await fetcher.get("https://example.com/")


async def test_redirects_are_followed_and_recorded() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://example.com/"})
        return httpx.Response(200, text="ok")

    fetcher = SafeFetcher(httpx.AsyncClient(transport=httpx.MockTransport(handler)), public_resolver)
    res = await fetcher.get("http://example.com/")
    assert res.history == ["http://example.com/", "https://example.com/"] and res.text == "ok"
