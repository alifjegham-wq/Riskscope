"""Proof of domain ownership, required before any active check runs.

Tokens are stateless: HMAC(secret, domain), so the server stores nothing. The
owner publishes the token either as a DNS TXT record at
``_riskscope-challenge.<domain>`` or as a file at
``https://<domain>/.well-known/riskscope-verify.txt``.
"""

from __future__ import annotations

import hashlib
import hmac

from .checks.base import DnsLookup
from .safety import SafeFetcher, Target, UnsafeTargetError

DNS_LABEL = "_riskscope-challenge"
WELL_KNOWN_PATH = ".well-known/riskscope-verify.txt"
PREFIX = "riskscope-verify="


def token_for(domain: str, secret: str) -> str:
    digest = hmac.new(secret.encode(), domain.lower().encode(), hashlib.sha256).hexdigest()
    return PREFIX + digest[:32]


async def is_verified(target: Target, secret: str, dns: DnsLookup, fetcher: SafeFetcher) -> bool:
    expected = token_for(target.registrable_hint, secret)
    for name in {target.host, target.registrable_hint}:
        records = await dns(f"{DNS_LABEL}.{name}", "TXT")
        if any(_same(r, expected) for r in records):
            return True
    try:
        res = await fetcher.get(target.url + WELL_KNOWN_PATH, follow_redirects=False)
    except (UnsafeTargetError, OSError):
        return False
    return res.response.status_code == 200 and _same(res.body[:256].decode("utf-8", "replace"), expected)


def _same(candidate: str, expected: str) -> bool:
    return hmac.compare_digest(candidate.strip().encode(), expected.encode())
