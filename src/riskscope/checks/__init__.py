"""Website checks. Add a new check by implementing `Check` and listing it in `default_checks`."""

from __future__ import annotations

from ..appscan.osv import VulnSource
from .base import Check, ScanContext
from .content import MixedContentCheck, SubresourceIntegrityCheck
from .cookies import CookieCheck
from .dns_email import DnsHardeningCheck, EmailAuthCheck
from .exposure import ExposedFilesCheck, SecurityTxtCheck
from .headers import CorsCheck, HttpsRedirectCheck, SecurityHeadersCheck
from .libraries import JsLibraryCheck
from .methods import HttpMethodsCheck
from .php import PhpVersionCheck
from .ports import OpenPortsCheck
from .profiles import DEFAULT_PROFILE, PROFILE_LABELS, PROFILES, normalize_profile, select_checks
from .subdomains import SubdomainSource, SubdomainTakeoverCheck
from .tls import TlsCheck
from .wordpress import WordPressCheck


def default_checks(vulns: VulnSource, subdomains: SubdomainSource | None = None) -> list[Check]:
    return [
        TlsCheck(),
        HttpsRedirectCheck(),
        SecurityHeadersCheck(),
        MixedContentCheck(),
        SubresourceIntegrityCheck(),
        CookieCheck(),
        CorsCheck(),
        HttpMethodsCheck(),
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


__all__ = [
    "DEFAULT_PROFILE",
    "PROFILES",
    "PROFILE_LABELS",
    "Check",
    "ScanContext",
    "default_checks",
    "normalize_profile",
    "select_checks",
]
