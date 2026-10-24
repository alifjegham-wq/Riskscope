import ipaddress

import httpx
import pytest
from fastapi.testclient import TestClient

from riskscope.config import Settings
from riskscope.ipscan import (
    CertProbe,
    HackerTargetSource,
    NullPassiveSource,
    discover_sites,
    looks_like_ip_target,
    parse_ip_target,
)
from riskscope.notify import LogMailer
from riskscope.safety import UnsafeTargetError
from riskscope.web.app import create_app

from .conftest import FakeDns, FakeVulns, public_resolver, site

SECRET = "ip-secret"


def ptr(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


class FakePassive:
    def __init__(self, by_ip: dict[str, list[str]] | None = None) -> None:
        self.by_ip = by_ip or {}

    async def hostnames(self, ip: str) -> list[str]:
        return self.by_ip.get(ip, [])


# ---- parsing ---------------------------------------------------------------


def test_looks_like_ip_target() -> None:
    assert looks_like_ip_target("8.8.8.8")
    assert looks_like_ip_target("8.8.8.0/24")
    assert looks_like_ip_target("2606:4700:4700::1111")
    assert not looks_like_ip_target("example.com")
    assert not looks_like_ip_target("not an ip")


def test_parse_single_and_cidr() -> None:
    single = parse_ip_target("8.8.8.8")
    assert single.is_single and single.label == "8.8.8.8" and single.addresses() == ["8.8.8.8"]
    block = parse_ip_target("8.8.8.0/30")
    assert not block.is_single and block.label == "8.8.8.0/30"
    assert block.addresses() == ["8.8.8.1", "8.8.8.2"]
    v6 = parse_ip_target("2606:4700:4700::1111")
    assert v6.is_single


@pytest.mark.parametrize(
    "raw",
    ["10.0.0.1", "192.168.1.1", "127.0.0.1", "::1", "169.254.169.254", "", "notanip", "8.8.8.8/x"],
)
def test_parse_rejects_bad_or_private(raw: str) -> None:
    with pytest.raises(UnsafeTargetError):
        parse_ip_target(raw)


def test_parse_rejects_oversized_block() -> None:
    with pytest.raises(UnsafeTargetError, match="too large"):
        parse_ip_target("8.8.0.0/16")
    assert parse_ip_target("8.8.8.0/24").network.num_addresses == 256  # at the limit, allowed


# ---- discovery -------------------------------------------------------------


async def test_discovery_merges_three_sources_and_forward_confirms() -> None:
    dns = FakeDns({(ptr("8.8.8.8"), "PTR"): ["dns.google.", "internal.corp."]})

    def cert(ip: str) -> list[str]:
        return ["dns.google", "*.edge-cdn.net", "localhost"] if ip == "8.8.8.8" else []

    passive = FakePassive({"8.8.8.8": ["extra.example.org"]})
    disc = await discover_sites(
        parse_ip_target("8.8.8.8"), dns=dns, resolver=public_resolver, passive=passive, cert_probe=cert
    )
    by_host = {s.host: s for s in disc.sites}
    assert set(by_host) == {"dns.google", "edge-cdn.net", "extra.example.org"}
    assert set(by_host["dns.google"].sources) == {"reverse DNS", "TLS certificate"}
    assert by_host["edge-cdn.net"].sources == ["TLS certificate"]  # wildcard stripped
    assert by_host["extra.example.org"].sources == ["passive DNS"]
    assert disc.ips_probed == 1
    # internal.corp (resolves private) and localhost (not a public hostname) are dropped.
    assert "internal.corp" not in by_host and "localhost" not in by_host


async def test_discovery_handles_unreachable_cert_and_no_results() -> None:
    def cert(ip: str) -> list[str]:
        raise ConnectionRefusedError("no 443")

    disc = await discover_sites(
        parse_ip_target("8.8.8.8"),
        dns=FakeDns(),
        resolver=public_resolver,
        passive=NullPassiveSource(),
        cert_probe=cert,
    )
    assert disc.sites == [] and disc.ips_probed == 1


async def test_discovery_caps_sites() -> None:
    def cert(ip: str) -> list[str]:
        return [f"host{i}.example.com" for i in range(10)]

    disc = await discover_sites(
        parse_ip_target("8.8.8.8"),
        dns=FakeDns(),
        resolver=public_resolver,
        passive=NullPassiveSource(),
        cert_probe=cert,
        max_sites=3,
    )
    assert len(disc.sites) == 3 and any("only the first 3" in n for n in disc.notes)


async def test_discovery_over_a_cidr_probes_each_address() -> None:
    def cert(ip: str) -> list[str]:
        return {"8.8.8.1": ["one.example.com"], "8.8.8.2": ["two.example.com"]}.get(ip, [])

    disc = await discover_sites(
        parse_ip_target("8.8.8.0/30"),
        dns=FakeDns(),
        resolver=public_resolver,
        passive=NullPassiveSource(),
        cert_probe=cert,
    )
    assert disc.ips_probed == 2
    assert {s.host: s.ip for s in disc.sites} == {"one.example.com": "8.8.8.1", "two.example.com": "8.8.8.2"}


async def test_hackertarget_parsing() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="a.example.com\nb.example.com / 8.8.8.8\n8.8.8.8\n")

    src = HackerTargetSource(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert await src.hostnames("8.8.8.8") == ["a.example.com", "b.example.com"]  # bare IP line dropped


def test_cert_hostnames_against_local_tls_server(monkeypatch: pytest.MonkeyPatch) -> None:
    # A real self-signed handshake proves the parser reads SAN/CN without validating the cert.
    pytest.importorskip("cryptography")
    import socket
    import ssl
    import threading
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cn.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("san.example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        certfile, keyfile = f"{d}/c.pem", f"{d}/k.pem"
        with open(certfile, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(keyfile, "wb") as fh:
            fh.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def serve() -> None:
            try:
                conn, _ = srv.accept()
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(16)
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        # cert_hostnames connects to :443; point it at our test port.
        import riskscope.ipscan as ip

        orig = socket.create_connection

        def fake_connect(addr: object, timeout: float | None = None) -> socket.socket:
            return orig(("127.0.0.1", port), timeout=timeout)

        monkeypatch.setattr(socket, "create_connection", fake_connect)
        try:
            names = ip.cert_hostnames("127.0.0.1")
        finally:
            srv.close()
    assert names == ["cn.example.com", "san.example.com"]


# ---- web integration -------------------------------------------------------


def make_ip_client(dns: FakeDns, cert_probe: CertProbe, passive: FakePassive | None = None) -> TestClient:
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(site({"/": httpx.Response(200, text="hi")})))
    from riskscope.checks.headers import SecurityHeadersCheck

    app = create_app(
        Settings(verify_secret=SECRET, database_path=":memory:", scheduler_enabled=False),
        http=upstream,
        vulns=FakeVulns(),
        resolver=public_resolver,
        dns=dns,
        checks=[SecurityHeadersCheck()],
        mailer=LogMailer(),
        passive=passive or FakePassive(),
        cert_probe=cert_probe,
    )
    return TestClient(app)


def test_scan_page_with_ip() -> None:
    dns = FakeDns({(ptr("8.8.8.8"), "PTR"): ["found.example.com."]})
    with make_ip_client(dns, lambda ip: []) as c:
        r = c.post("/scan", data={"target": "8.8.8.8"})
        assert r.status_code == 200
        assert "found.example.com" in r.text and "Found on 8.8.8.8 via reverse DNS" in r.text
        assert "No Content-Security-Policy" in r.text  # the discovered site was really scanned


def test_scan_page_ip_with_no_site() -> None:
    with make_ip_client(FakeDns(), lambda ip: []) as c:
        r = c.post("/scan", data={"target": "8.8.8.8"})
        assert r.status_code == 200 and "No website found" in r.text


def test_bulk_accepts_ip_and_scans_hosts_passively() -> None:
    dns = FakeDns({(ptr("8.8.8.8"), "PTR"): ["found.example.com."]})
    with make_ip_client(dns, lambda ip: []) as c:
        r = c.post("/bulk", data={"targets": "8.8.8.8"})
        assert r.status_code == 200
        assert "found.example.com" in r.text
        assert "found on 8.8.8.8 · passive checks only" in r.text
        assert "No Content-Security-Policy" in r.text  # the discovered host was really scanned
        assert 'data-export="csv"' in r.text


def test_bulk_ip_with_no_site_reports_nothing_found() -> None:
    with make_ip_client(FakeDns(), lambda ip: []) as c:
        body = c.post("/api/bulk-scan", data={"targets": ["8.8.8.8"]}).json()
        assert body["items"][0]["error"] == "No sites found on this IP or range"


def test_api_ip_scan_and_domain_guard() -> None:
    dns = FakeDns({(ptr("8.8.8.8"), "PTR"): ["found.example.com."]})
    with make_ip_client(dns, lambda ip: ["cert.example.com"]) as c:
        body = c.get("/api/ip-scan", params={"target": "8.8.8.8"}).json()
        assert body["target"] == "8.8.8.8" and body["ips_probed"] == 1
        hosts = {s["host"]: s for s in body["sites"]}
        assert "found.example.com" in hosts and "cert.example.com" in hosts
        assert hosts["found.example.com"]["found_via"] == ["reverse DNS"]
        assert hosts["found.example.com"]["report"]["grade"] in "ABCDF"
        # The IP guard sends IP targets to the right endpoint.
        r = c.get("/api/scan", params={"target": "8.8.8.8"})
        assert r.status_code == 400 and "ip-scan" in r.json()["detail"]
        assert c.get("/api/ip-scan", params={"target": "10.0.0.1"}).status_code == 400
