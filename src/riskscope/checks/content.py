"""Mixed content: an HTTPS page that pulls sub-resources over plain http://."""

from __future__ import annotations

import re

from ..models import Category, Finding, Severity
from .base import ScanContext

# Active mixed content (blocked/again by browsers, breaks the page and security): scripts, styles, iframes.
_ACTIVE = re.compile(
    r"""<(?:script|iframe)\b[^>]*\bsrc\s*=\s*["'](http://[^"']+)["']"""
    r"""|<link\b[^>]*\bhref\s*=\s*["'](http://[^"']+)["'][^>]*\brel\s*=\s*["']?stylesheet"""
    r"""|<link\b[^>]*\brel\s*=\s*["']?stylesheet[^>]*\bhref\s*=\s*["'](http://[^"']+)["']""",
    re.I,
)
# Passive mixed content (images, media): a weaker warning.
_PASSIVE = re.compile(r"""<(?:img|audio|video|source)\b[^>]*\bsrc\s*=\s*["'](http://[^"']+)["']""", re.I)


def _urls(matches: list[tuple[str, ...]] | list[str]) -> list[str]:
    out: list[str] = []
    for m in matches:
        if isinstance(m, tuple):
            out.extend(u for u in m if u)
        elif m:
            out.append(m)
    return sorted(set(out))


class MixedContentCheck:
    name = "mixed_content"
    title = "Mixed content (http resources on an https page)"
    active = False

    async def run(self, ctx: ScanContext) -> list[Finding]:
        res = await ctx.homepage()
        if not str(res.response.url).startswith("https://"):
            return []
        html = res.text[:1_000_000]
        active = _urls(_ACTIVE.findall(html))
        passive = _urls(_PASSIVE.findall(html))
        out: list[Finding] = []
        if active:
            out.append(
                Finding(
                    id="content.mixed.active",
                    title="Scripts or styles are loaded over insecure http://",
                    severity=Severity.MEDIUM,
                    category=Category.HEADERS,
                    description=(
                        "This HTTPS page loads scripts, stylesheets or frames over plain http://. Browsers block "
                        "most of these (breaking the page), and any that load can be tampered with on the network."
                    ),
                    evidence="\n".join(active[:10]) + (f"\n… and {len(active) - 10} more" if len(active) > 10 else ""),
                    fix="Change these URLs to https:// (or protocol-relative //), and host the resource over HTTPS.",
                )
            )
        if passive:
            out.append(
                Finding(
                    id="content.mixed.passive",
                    title="Images or media are loaded over insecure http://",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    description=(
                        "Images/media loaded over http:// can be swapped on the network and trigger warnings."
                    ),
                    evidence="\n".join(passive[:10])
                    + (f"\n… and {len(passive) - 10} more" if len(passive) > 10 else ""),
                    fix="Serve these over https://.",
                )
            )
        return out
