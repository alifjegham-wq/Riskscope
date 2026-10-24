"""Front-end JavaScript libraries with known vulnerabilities (detected from script URLs)."""

from __future__ import annotations

import re

from ..appscan.osv import Package, VulnSource, findings_for
from ..models import Category, Finding
from .base import ScanContext

# script URL fragment name -> npm package name
LIBRARIES = {
    "jquery": "jquery",
    "jquery-ui": "jquery-ui",
    "bootstrap": "bootstrap",
    "angular": "angular",
    "lodash": "lodash",
    "moment": "moment",
    "handlebars": "handlebars",
    "underscore": "underscore",
    "vue": "vue",
    "dompurify": "dompurify",
    "react": "react",
    "react-dom": "react-dom",
}

_SRC = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
_NAMES = "|".join(sorted((re.escape(n) for n in LIBRARIES), key=len, reverse=True))
# Matches jquery-3.4.1.min.js, jquery/3.4.1/, bootstrap@4.3.1, lodash.js/4.17.15, ...
_LIB = re.compile(
    rf"(?<![a-z0-9])({_NAMES})(?:\.js|\.min\.js)?[@/\-](\d+\.\d+\.\d+)(?![\d])",
    re.I,
)


def detect_libraries(html: str) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for src in _SRC.findall(html):
        for name, version in _LIB.findall(src):
            found.setdefault(LIBRARIES[name.lower()], version)
    return sorted(found.items())


class JsLibraryCheck:
    name = "js_libraries"
    title = "Front-end libraries with known vulnerabilities"
    active = False

    def __init__(self, vulns: VulnSource) -> None:
        self.vulns = vulns

    async def run(self, ctx: ScanContext) -> list[Finding]:
        home = await ctx.homepage()
        libs = detect_libraries(home.text)
        if not libs:
            return []
        pkgs = [Package("npm", name, version, source="a <script> tag on the homepage") for name, version in libs]
        return findings_for(await self.vulns.lookup(pkgs), Category.SOFTWARE)
