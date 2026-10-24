"""Website checks. Add a new check by implementing `Check` and listing it in `default_checks`."""

from __future__ import annotations

from ..appscan.osv import VulnSource
from .base import Check, ScanContext
from .content import MixedContentCheck
from .cookies import CookieCheck
from .dns_email import DnsHardeningCheck, EmailAuthCheck
from .exposure import ExposedFilesCheck, SecurityTxtCheck
from .headers import CorsCheck, HttpsRedirectCheck, SecurityHeadersCheck
from .libraries import JsLibraryCheck
from .php import PhpVersionCheck
from .ports import OpenPortsCheck
from .subdomains import SubdomainSource, SubdomainTakeoverCheck
from .tls import TlsCheck
from .wordpress import WordPressCheck


def default_checks(vulns: VulnSource, subdomains: SubdomainSource | None = None) -> list[Check]:
    return [
        TlsCheck(),
        HttpsRedirectCheck(),
        SecurityHeadersCheck(),
        MixedContentCheck(),
        CookieCheck(),
        CorsCheck(),
        EmailAuthCheck(),
        DnsHardeningCheck(),
        ExposedFilesCheck(),
        SecurityTxtCheck(),
        SubdomainTakeoverCheck(subdomains),
        JsLibraryCheck(vulns),
        PhpVersionCheck(),
        WordPressCheck(),
        OpenPortsCheck(),
    ]


__all__ = ["Check", "ScanContext", "default_checks"]
