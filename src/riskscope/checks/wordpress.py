"""WordPress-specific exposures: version leak, user enumeration, XML-RPC."""

from __future__ import annotations

import json
import re

from ..models import Category, Finding, Severity
from ..safety import UnsafeTargetError
from .base import ScanContext

_WP_HINT = re.compile(r"/wp-(?:content|includes)/|<meta[^>]+name=[\"']generator[\"'][^>]+WordPress", re.I)
_VERSION = re.compile(r"[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)")


def is_wordpress(html: str) -> bool:
    return bool(_WP_HINT.search(html[:200_000]))


class WordPressCheck:
    name = "wordpress"
    title = "WordPress exposures"
    active = False

    async def run(self, ctx: ScanContext) -> list[Finding]:
        home = await ctx.homepage()
        if not is_wordpress(home.text):
            return []
        base = ctx.target.url.rstrip("/")
        out: list[Finding] = []

        # Version from readme.html (helps attackers match known exploits to the exact version).
        readme = await self._get(ctx, base + "/readme.html")
        if readme is not None and b"wordpress" in readme[:4096].lower():
            m = _VERSION.search(readme[:4096].decode("utf-8", "replace"))
            out.append(
                Finding(
                    id="wordpress.version_disclosure",
                    title="WordPress version is published at /readme.html" + (f" ({m.group(1)})" if m else ""),
                    severity=Severity.LOW,
                    category=Category.SOFTWARE,
                    description=(
                        "readme.html reveals the exact WordPress version, making known exploits easy to target."
                    ),
                    evidence=f"GET /readme.html -> 200{' , version ' + m.group(1) if m else ''}",
                    fix="Delete or block /readme.html, and keep WordPress updated.",
                )
            )

        # User enumeration via the REST API (gives attackers valid usernames to brute-force).
        users = await self._get(ctx, base + "/wp-json/wp/v2/users")
        names = _usernames(users)
        if names:
            out.append(
                Finding(
                    id="wordpress.user_enumeration",
                    title="WordPress usernames are listed by the REST API",
                    severity=Severity.MEDIUM,
                    category=Category.EXPOSURE,
                    description=(
                        "/wp-json/wp/v2/users returns valid usernames, which attackers use as the first half of a "
                        "password brute-force."
                    ),
                    evidence="Usernames: " + ", ".join(names[:5]) + (" …" if len(names) > 5 else ""),
                    fix="Restrict the users endpoint (a security plugin can) and require strong passwords + 2FA.",
                )
            )

        # XML-RPC enabled (used to amplify brute-force and for pingback DDoS).
        xmlrpc = await self._get(ctx, base + "/xmlrpc.php")
        if xmlrpc is not None and b"XML-RPC server accepts POST requests only" in xmlrpc:
            out.append(
                Finding(
                    id="wordpress.xmlrpc_enabled",
                    title="WordPress XML-RPC is enabled",
                    severity=Severity.LOW,
                    category=Category.EXPOSURE,
                    description=(
                        "xmlrpc.php lets attackers try many passwords in one request and can be abused for "
                        "pingback DDoS."
                    ),
                    evidence="GET /xmlrpc.php -> XML-RPC endpoint responded",
                    fix="Disable XML-RPC if you don't use it (a plugin or a server rule can block xmlrpc.php).",
                )
            )
        return out

    @staticmethod
    async def _get(ctx: ScanContext, url: str) -> bytes | None:
        try:
            res = await ctx.fetcher.get(url, follow_redirects=False)
        except (UnsafeTargetError, OSError):
            return None
        return res.body if res.response.status_code == 200 else None


def _usernames(body: bytes | None) -> list[str]:
    if not body:
        return []
    try:
        data = json.loads(body[:200_000])
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [str(u["slug"]) for u in data if isinstance(u, dict) and u.get("slug")]
