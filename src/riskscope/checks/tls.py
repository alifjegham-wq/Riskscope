"""TLS certificate validity/expiry and legacy protocol support."""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..models import Category, Finding, Severity
from ..safety import assert_public_host
from .base import ScanContext

TIMEOUT = 8.0


@dataclass
class TlsInfo:
    verify_error: str | None = None
    protocol: str | None = None
    not_after: float | None = None  # epoch seconds
    legacy_protocols: list[str] = field(default_factory=list)


def _handshake(ip: str, host: str, context: ssl.SSLContext) -> ssl.SSLSocket:
    raw = socket.create_connection((ip, 443), timeout=TIMEOUT)
    try:
        return context.wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise


def probe_tls(host: str, ip: str) -> TlsInfo:
    """Blocking probe; we connect to the already-validated IP so DNS cannot be rebound in between."""
    info = TlsInfo()
    try:
        with _handshake(ip, host, ssl.create_default_context()) as s:
            info.protocol = s.version()
            cert = s.getpeercert()
            if cert and "notAfter" in cert:
                info.not_after = ssl.cert_time_to_seconds(str(cert["notAfter"]))
    except ssl.SSLCertVerificationError as exc:
        info.verify_error = exc.verify_message or str(exc)

    for name, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            ctx.minimum_version = version
            ctx.maximum_version = version
            with _handshake(ip, host, ctx):
                info.legacy_protocols.append(name)
        except (ssl.SSLError, OSError, ValueError):
            # Refused by the server, or our OpenSSL build cannot speak it (then we cannot tell).
            continue
    return info


class TlsCheck:
    name = "tls"
    title = "TLS certificate and protocols"
    active = False

    def __init__(self, probe: Callable[[str, str], TlsInfo] = probe_tls) -> None:
        self.probe = probe

    async def run(self, ctx: ScanContext) -> list[Finding]:
        addrs = await assert_public_host(ctx.target.host, ctx.fetcher.resolver)
        try:
            info = await asyncio.to_thread(self.probe, ctx.target.host, addrs[0])
        except OSError as exc:
            return [
                Finding(
                    id="tls.unreachable",
                    title="The site does not answer on HTTPS (port 443)",
                    severity=Severity.HIGH,
                    category=Category.TLS,
                    description="Without HTTPS everything visitors send and receive can be read and changed.",
                    evidence=str(exc),
                    fix="Enable HTTPS. Free certificates are available from Let's Encrypt.",
                    references=["https://letsencrypt.org/getting-started/"],
                )
            ]

        out: list[Finding] = []
        if info.verify_error:
            out.append(
                Finding(
                    id="tls.cert.invalid",
                    title="The HTTPS certificate is not trusted",
                    severity=Severity.HIGH,
                    category=Category.TLS,
                    description="Browsers show a full-page warning; visitors cannot tell your site from an impostor.",
                    evidence=info.verify_error,
                    fix="Install a certificate from a public CA that covers this exact hostname, with its full chain.",
                )
            )
        if info.not_after is not None:
            days = (info.not_after - time.time()) / 86400
            if days < 0:
                sev, title = Severity.CRITICAL, "The HTTPS certificate has expired"
            elif days < 14:
                sev, title = Severity.HIGH, f"The HTTPS certificate expires in {int(days)} days"
            elif days < 30:
                sev, title = Severity.MEDIUM, f"The HTTPS certificate expires in {int(days)} days"
            else:
                sev, title = None, ""
            if sev is not None:
                out.append(
                    Finding(
                        id="tls.cert.expiry",
                        title=title,
                        severity=sev,
                        category=Category.TLS,
                        description="An expired certificate takes the site offline for most visitors.",
                        evidence=time.strftime("Expires %Y-%m-%d", time.gmtime(info.not_after)),
                        fix="Renew now and automate renewal (e.g. certbot or your host's auto-SSL).",
                    )
                )
        if info.legacy_protocols:
            out.append(
                Finding(
                    id="tls.legacy_protocols",
                    title=f"Outdated encryption still accepted: {', '.join(info.legacy_protocols)}",
                    severity=Severity.MEDIUM,
                    category=Category.TLS,
                    description="TLS 1.0 and 1.1 have known weaknesses and are retired by all major browsers.",
                    fix="Allow only TLS 1.2 and TLS 1.3.",
                    snippets={
                        "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
                        "Apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
                    },
                    references=["https://ssl-config.mozilla.org/"],
                )
            )
        return out
