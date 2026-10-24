"""Cookie flags on the homepage response."""

from __future__ import annotations

import re

from ..models import Category, Finding, Severity
from .base import ScanContext

# Cookie names that usually carry a login session.
_SESSIONISH = re.compile(r"sess|sid|auth|token|login|jwt|remember", re.I)


def parse_set_cookie(header: str) -> tuple[str, set[str], str | None]:
    """Return (name, lower-cased flag names, samesite value)."""
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    flags: set[str] = set()
    samesite: str | None = None
    for attr in parts[1:]:
        key, _, value = attr.partition("=")
        key = key.strip().lower()
        flags.add(key)
        if key == "samesite":
            samesite = value.strip().lower()
    return name, flags, samesite


class CookieCheck:
    name = "cookies"
    title = "Cookie security flags"
    active = False

    async def run(self, ctx: ScanContext) -> list[Finding]:
        res = await ctx.homepage()
        out: list[Finding] = []
        for header in res.response.headers.get_list("set-cookie"):
            name, flags, samesite = parse_set_cookie(header)
            missing = []
            if "secure" not in flags:
                missing.append("Secure")
            if "httponly" not in flags:
                missing.append("HttpOnly")
            if samesite is None:
                missing.append("SameSite")
            elif samesite == "none" and "secure" not in flags:
                missing.append("Secure (required with SameSite=None)")
            if not missing:
                continue
            session = bool(_SESSIONISH.search(name))
            out.append(
                Finding(
                    id=f"cookies.flags.{name}",
                    title=f"Cookie '{name}' is missing {', '.join(missing)}",
                    severity=Severity.MEDIUM if session else Severity.LOW,
                    category=Category.COOKIES,
                    description=(
                        "Secure keeps the cookie off unencrypted connections, HttpOnly hides it from scripts "
                        "(limiting XSS damage) and SameSite blocks most cross-site request forgery."
                        + (" This looks like a login/session cookie, so it matters more." if session else "")
                    ),
                    evidence=header.split(";", 1)[0].split("=", 1)[0] + "=…; " + "; ".join(sorted(flags)),
                    fix=f"Set the cookie with: {'; '.join(m.split(' ')[0] for m in missing)}.",
                    snippets={"Example": f"Set-Cookie: {name}=<value>; Path=/; Secure; HttpOnly; SameSite=Lax"},
                )
            )
        return out
