"""Website checks. Add a new check by implementing `Check` and listing it in `default_checks`."""

from __future__ import annotations

from ..appscan.osv import VulnSource
from .base import Check, ScanContext
from .cookies import CookieCheck
from .dns_email import DnsHardeningCheck, EmailAuthCheck
from .exposure import ExposedFilesCheck, SecurityTxtCheck
from .headers import CorsCheck, HttpsRedirectCheck, SecurityHeadersCheck
from .libraries import JsLibraryCheck
from .ports import OpenPortsCheck
from .tls import TlsCheck


def default_checks(vulns: VulnSource) -> list[Check]:
    return [
        TlsCheck(),
        HttpsRedirectCheck(),
        SecurityHeadersCheck(),
        CookieCheck(),
        CorsCheck(),
        EmailAuthCheck(),
        DnsHardeningCheck(),
        ExposedFilesCheck(),
        SecurityTxtCheck(),
        JsLibraryCheck(vulns),
        OpenPortsCheck(),
    ]


__all__ = ["Check", "ScanContext", "default_checks"]
