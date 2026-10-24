"""TLS certificate validity/expiry and legacy protocol support."""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

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
    key_type: str = ""
    key_bits: int | None = None
    sig_hash: str = ""  # e.g. "sha256", "sha1"
    validity_days: int | None = None


def _handshake(ip: str, host: str, context: ssl.SSLContext) -> ssl.SSLSocket:
    raw = socket.create_connection((ip, 443), timeout=TIMEOUT)
    try:
        return context.wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise


def _fill_cert_info(info: TlsInfo, cert: x509.Certificate) -> None:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        info.key_type, info.key_bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        info.key_type, info.key_bits = "EC", pub.curve.key_size
    if cert.signature_hash_algorithm is not None:
        info.sig_hash = cert.signature_hash_algorithm.name.lower()
    info.validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days


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

    try:  # parse the served cert regardless of trust, to inspect key/signature/validity
        no_verify = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        no_verify.check_hostname = False
        no_verify.verify_mode = ssl.CERT_NONE
        with _handshake(ip, host, no_verify) as s:
            der = s.getpeercert(binary_form=True)
        if der:
            _fill_cert_info(info, x509.load_der_x509_certificate(der))
    except (ssl.SSLError, OSError, ValueError):
        pass

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
        if info.key_type == "RSA" and info.key_bits is not None and info.key_bits < 2048:
            out.append(
                Finding(
                    id="tls.weak_key",
                    title=f"The certificate uses a weak {info.key_bits}-bit RSA key",
                    severity=Severity.HIGH,
                    category=Category.TLS,
                    description="RSA keys under 2048 bits can be broken; browsers reject them.",
                    evidence=f"{info.key_type} {info.key_bits}-bit",
                    fix="Reissue the certificate with at least a 2048-bit RSA key (or a 256-bit ECDSA key).",
                )
            )
        if info.sig_hash in ("sha1", "md5"):
            out.append(
                Finding(
                    id="tls.weak_signature",
                    title=f"The certificate is signed with {info.sig_hash.upper()}",
                    severity=Severity.HIGH,
                    category=Category.TLS,
                    description=f"{info.sig_hash.upper()} signatures are forgeable and distrusted by browsers.",
                    evidence=f"signature algorithm: {info.sig_hash}",
                    fix="Reissue the certificate with a SHA-256 (or stronger) signature.",
                )
            )
        if info.validity_days is not None and info.validity_days > 398:
            out.append(
                Finding(
                    id="tls.long_validity",
                    title=f"The certificate is valid for {info.validity_days} days",
                    severity=Severity.LOW,
                    category=Category.TLS,
                    description=(
                        "Public certificates must be valid for at most 398 days; a longer-lived one is "
                        "non-compliant and newer browsers may reject it. A long-lived leaf cert is also a bigger "
                        "risk if its key is ever stolen."
                    ),
                    evidence=f"validity: {info.validity_days} days",
                    fix="Issue certificates for 398 days or less and automate renewal.",
                )
            )
        return out
