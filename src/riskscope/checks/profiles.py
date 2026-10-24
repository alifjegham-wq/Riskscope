"""Scan profiles: named subsets of checks, so a scan can be narrowed or sped up.

A profile maps to the set of check ``name``s it runs; ``None`` means "every check".
Profiles never add behaviour — they only restrict which of the registered checks run — so a
narrower profile is always a subset of the full scan and can never scan more.
"""

from __future__ import annotations

from .base import Check

# Ordered for display. The first entry is the default.
PROFILES: dict[str, frozenset[str] | None] = {
    "full": None,
    "quick": frozenset(
        {"tls", "https_redirect", "security_headers", "mixed_content", "sri", "cookies", "cors", "http_methods"}
    ),
    "headers": frozenset(
        {"tls", "https_redirect", "security_headers", "mixed_content", "cookies", "cors", "http_methods"}
    ),
    "exposure": frozenset({"exposed_files", "security_txt", "wordpress", "php_version"}),
    "email": frozenset({"email_auth", "dns_hardening", "subdomain_takeover"}),
}

PROFILE_LABELS: dict[str, str] = {
    "full": "Full scan (everything)",
    "quick": "Quick scan (headers, TLS, cookies, methods)",
    "headers": "Headers & encryption only",
    "exposure": "Exposed files & software only",
    "email": "Email spoofing & DNS only",
}

DEFAULT_PROFILE = "full"


def normalize_profile(value: str | None) -> str:
    """Return a known profile name, falling back to the default for anything unrecognised."""
    return value if value in PROFILES else DEFAULT_PROFILE


def select_checks(checks: list[Check], profile: str | None) -> list[Check]:
    names = PROFILES.get(normalize_profile(profile))
    if names is None:
        return checks
    return [c for c in checks if c.name in names]
