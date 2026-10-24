"""HTTP response headers: HTTPS redirect, HSTS, CSP, framing, sniffing, disclosure, CORS."""

from __future__ import annotations

import re

from ..models import Category, Finding, Severity
from .base import ScanContext

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days
_VERSION = re.compile(r"\d+\.\d+")
CORS_PROBE_ORIGIN = "https://riskscope-cors-probe.invalid"

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"


def _hdr(name: str, value: str) -> dict[str, str]:
    return {
        "nginx": f'add_header {name} "{value}" always;',
        "Apache": f'Header always set {name} "{value}"',
    }


class HttpsRedirectCheck:
    name = "https_redirect"
    title = "Plain HTTP redirects to HTTPS"
    active = False

    async def run(self, ctx: ScanContext) -> list[Finding]:
        res = await ctx.fetcher.get(f"http://{ctx.target.host}/")
        if str(res.response.url).startswith("https://") or res.history[-1].startswith("https://"):
            return []
        return [
            Finding(
                id="https.no_redirect",
                title="Visitors using http:// are not sent to the secure site",
                severity=Severity.MEDIUM,
                category=Category.TLS,
                description=(
                    "Anyone who types your address without https:// gets an unencrypted page that can be "
                    "read or altered on public Wi-Fi."
                ),
                evidence=f"http://{ctx.target.host}/ answered {res.response.status_code} without redirecting",
                fix="Redirect every http:// request to https:// with a 301.",
                snippets={
                    "nginx": "server { listen 80; server_name _; return 301 https://$host$request_uri; }",
                    "Apache": "RewriteEngine On\nRewriteCond %{HTTPS} off\n"
                    "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]",
                },
            )
        ]


class SecurityHeadersCheck:
    name = "security_headers"
    title = "Browser security headers"
    active = False

    async def run(self, ctx: ScanContext) -> list[Finding]:
        res = await ctx.homepage()
        h = res.response.headers
        out: list[Finding] = []

        hsts = h.get("strict-transport-security")
        if not hsts:
            out.append(
                Finding(
                    id="headers.hsts.missing",
                    title="HSTS is not enabled",
                    severity=Severity.MEDIUM,
                    category=Category.HEADERS,
                    description=(
                        "Without Strict-Transport-Security a browser can be tricked into loading your site "
                        "over plain HTTP (SSL stripping)."
                    ),
                    fix="Send Strict-Transport-Security on every HTTPS response.",
                    snippets=_hdr("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
                    references=[MDN + "Strict-Transport-Security"],
                )
            )
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < HSTS_MIN_MAX_AGE:
                out.append(
                    Finding(
                        id="headers.hsts.short",
                        title="HSTS max-age is too short",
                        severity=Severity.LOW,
                        category=Category.HEADERS,
                        description="A short HSTS lifetime leaves returning visitors unprotected sooner.",
                        evidence=f"Strict-Transport-Security: {hsts}",
                        fix="Use a max-age of at least 180 days (31536000 = one year is typical).",
                        snippets=_hdr("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
                    )
                )

        csp = h.get("content-security-policy", "")
        if not csp:
            out.append(
                Finding(
                    id="headers.csp.missing",
                    title="No Content-Security-Policy",
                    severity=Severity.MEDIUM,
                    category=Category.HEADERS,
                    description=(
                        "A CSP is the main browser-side defence against cross-site scripting (XSS): it limits "
                        "where scripts may load from."
                    ),
                    fix=(
                        "Start with a report-only policy, watch the reports, then enforce it. "
                        "A strict starting point is shown below."
                    ),
                    snippets=_hdr(
                        "Content-Security-Policy",
                        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
                    ),
                    references=[MDN + "Content-Security-Policy"],
                )
            )
        else:
            script_src = _directive(csp, "script-src") or _directive(csp, "default-src") or ""
            if "'unsafe-inline'" in script_src and "'nonce-" not in script_src and "'sha" not in script_src:
                out.append(
                    Finding(
                        id="headers.csp.unsafe_inline",
                        title="CSP allows inline scripts",
                        severity=Severity.LOW,
                        category=Category.HEADERS,
                        description="'unsafe-inline' in script-src removes most of the XSS protection a CSP gives.",
                        evidence=f"script-src {script_src}",
                        fix="Replace 'unsafe-inline' with nonces or hashes for the inline scripts you need.",
                    )
                )
            if "'unsafe-eval'" in script_src:
                out.append(
                    Finding(
                        id="headers.csp.unsafe_eval",
                        title="CSP allows eval() in scripts",
                        severity=Severity.LOW,
                        category=Category.HEADERS,
                        description="'unsafe-eval' lets pages run strings as code, which XSS payloads rely on.",
                        evidence=f"script-src {script_src}",
                        fix="Remove 'unsafe-eval' and refactor any code that uses eval()/new Function().",
                    )
                )
            if any(src in ("*", "http:", "https:") for src in script_src.split()):
                out.append(
                    Finding(
                        id="headers.csp.wildcard_script",
                        title="CSP lets scripts load from anywhere",
                        severity=Severity.MEDIUM,
                        category=Category.HEADERS,
                        description=(
                            "A wildcard (*) or bare http:/https: source in script-src means a script from any "
                            "site is allowed, which defeats the CSP's XSS protection."
                        ),
                        evidence=f"script-src {script_src}",
                        fix="List the exact origins your scripts come from instead of a wildcard.",
                    )
                )
            if _directive(csp, "object-src") is None and _directive(csp, "default-src") is None:
                out.append(
                    Finding(
                        id="headers.csp.no_object_src",
                        title="CSP does not restrict plugins (object-src)",
                        severity=Severity.LOW,
                        category=Category.HEADERS,
                        description="Without object-src, Flash/Java-style plugin content can still be embedded.",
                        fix="Add object-src 'none' to the policy.",
                    )
                )
            if _directive(csp, "base-uri") is None:
                out.append(
                    Finding(
                        id="headers.csp.no_base_uri",
                        title="CSP does not set base-uri",
                        severity=Severity.LOW,
                        category=Category.HEADERS,
                        description="Without base-uri, an injected <base> tag can redirect every relative URL.",
                        fix="Add base-uri 'self' (or 'none') to the policy.",
                    )
                )

        if "x-frame-options" not in h and not _directive(csp, "frame-ancestors"):
            out.append(
                Finding(
                    id="headers.framing.missing",
                    title="Pages can be embedded by other sites (clickjacking)",
                    severity=Severity.MEDIUM,
                    category=Category.HEADERS,
                    description=(
                        "Another site can load your pages in an invisible frame and trick users into clicking "
                        "buttons they cannot see."
                    ),
                    fix="Set frame-ancestors in your CSP (preferred) or X-Frame-Options.",
                    snippets=_hdr("X-Frame-Options", "SAMEORIGIN"),
                    references=[MDN + "X-Frame-Options"],
                )
            )

        if h.get("x-content-type-options", "").lower() != "nosniff":
            out.append(
                Finding(
                    id="headers.nosniff.missing",
                    title="X-Content-Type-Options is not set",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    description="Browsers may guess file types and run an uploaded file as a script.",
                    fix="Send X-Content-Type-Options: nosniff.",
                    snippets=_hdr("X-Content-Type-Options", "nosniff"),
                )
            )

        if "referrer-policy" not in h:
            out.append(
                Finding(
                    id="headers.referrer.missing",
                    title="No Referrer-Policy",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    description="Full page URLs (which may contain tokens or IDs) leak to every site you link to.",
                    fix="Send Referrer-Policy: strict-origin-when-cross-origin.",
                    snippets=_hdr("Referrer-Policy", "strict-origin-when-cross-origin"),
                )
            )

        if "permissions-policy" not in h:
            out.append(
                Finding(
                    id="headers.permissions.missing",
                    title="No Permissions-Policy",
                    severity=Severity.INFO,
                    category=Category.HEADERS,
                    description="Optional hardening: switch off browser features (camera, mic...) you never use.",
                    snippets=_hdr("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
                )
            )

        disclosed = [f"{k}: {h[k]}" for k in ("server", "x-powered-by", "x-aspnet-version") if k in h]
        disclosed = [d for d in disclosed if _VERSION.search(d)]
        if disclosed:
            out.append(
                Finding(
                    id="headers.version_disclosure",
                    title="Server software versions are advertised",
                    severity=Severity.LOW,
                    category=Category.SOFTWARE,
                    description="Exact versions let attackers look up which known exploits apply to you.",
                    evidence="; ".join(disclosed),
                    fix="Hide version numbers in response headers.",
                    snippets={
                        "nginx": "server_tokens off;",
                        "Apache": "ServerTokens Prod\nServerSignature Off",
                        "PHP": "expose_php = Off   ; in php.ini",
                    },
                )
            )
        return out


class CorsCheck:
    name = "cors"
    title = "Cross-origin resource sharing (CORS)"
    active = False

    async def run(self, ctx: ScanContext) -> list[Finding]:
        res = await ctx.fetcher.get(ctx.target.url, headers={"Origin": CORS_PROBE_ORIGIN})
        h = res.response.headers
        acao = h.get("access-control-allow-origin", "")
        creds = h.get("access-control-allow-credentials", "").lower() == "true"
        if acao not in (CORS_PROBE_ORIGIN, "null"):
            return []
        return [
            Finding(
                id="cors.reflected_origin",
                title="Any website may read your responses (CORS reflects the Origin)",
                severity=Severity.HIGH if creds else Severity.MEDIUM,
                category=Category.HEADERS,
                description=(
                    "The server echoes whatever Origin it is sent. "
                    + (
                        "Because credentials are allowed too, a malicious site can read logged-in users' data."
                        if creds
                        else "Any site can read these responses from a visitor's browser."
                    )
                ),
                evidence=f"Origin: {CORS_PROBE_ORIGIN} -> Access-Control-Allow-Origin: {acao}"
                + ("; Access-Control-Allow-Credentials: true" if creds else ""),
                fix="Only return Access-Control-Allow-Origin for an explicit allow-list of your own origins.",
                references=["https://portswigger.net/web-security/cors"],
            )
        ]


def _directive(csp: str, name: str) -> str | None:
    for part in csp.split(";"):
        tokens = part.strip().split(None, 1)
        if tokens and tokens[0].lower() == name:
            return tokens[1] if len(tokens) > 1 else ""
    return None
