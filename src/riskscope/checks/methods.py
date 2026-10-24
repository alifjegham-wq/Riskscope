"""Dangerous HTTP methods advertised by the server (read from an OPTIONS request)."""

from __future__ import annotations

import httpx

from ..models import Category, Finding, Severity
from ..safety import UnsafeTargetError
from .base import ScanContext

# Methods that should not be reachable on a normal public site.
_TRACE = {"TRACE", "TRACK"}  # enable Cross-Site Tracing (can echo cookies/auth headers)
_WRITE = {"PUT", "DELETE", "PATCH", "CONNECT"}  # write/tunnel verbs; risky if unauthenticated


class HttpMethodsCheck:
    name = "http_methods"
    title = "HTTP methods"
    active = False

    async def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = await ctx.fetcher.options(ctx.target.url)
        except (UnsafeTargetError, httpx.HTTPError, OSError):
            return []
        allow = resp.headers.get("allow", "") + "," + resp.headers.get("public", "")
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        if not methods:
            return []

        out: list[Finding] = []
        trace = methods & _TRACE
        if trace:
            out.append(
                Finding(
                    id="methods.trace",
                    title="TRACE/TRACK method is enabled",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    description=(
                        "TRACE echoes the request back, including cookies and auth headers. Combined with "
                        "another flaw it enables Cross-Site Tracing (stealing HttpOnly cookies)."
                    ),
                    evidence=f"OPTIONS Allow: {', '.join(sorted(methods))}",
                    fix="Disable TRACE/TRACK on the web server.",
                    snippets={
                        "nginx": "if ($request_method ~ ^(TRACE|TRACK)$) { return 405; }",
                        "Apache": "TraceEnable off",
                    },
                )
            )
        write = methods & _WRITE
        if write:
            out.append(
                Finding(
                    id="methods.write_verbs",
                    title="Write methods are advertised",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    description=(
                        f"The server advertises {', '.join(sorted(write))}. If any of these are reachable "
                        "without authentication, an attacker may change or delete content."
                    ),
                    evidence=f"OPTIONS Allow: {', '.join(sorted(methods))}",
                    fix="Allow only the methods each endpoint needs (usually GET/HEAD/POST), and require "
                    "authentication for writes.",
                )
            )
        return out
