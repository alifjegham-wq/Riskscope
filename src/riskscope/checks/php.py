"""PHP runtime version against known critical PHP advisories and end-of-life branches.

The advisory data is a table on purpose: when the next PHP emergency release
ships, add an entry to ``ADVISORIES`` (and move ``OLDEST_SUPPORTED`` when a
branch reaches end of life) instead of writing a new check.

Detection is passive. The version comes from response headers
(``X-Powered-By: PHP/8.3.12``) or from an exposed ``phpinfo()`` page. When PHP
is evident but its version is hidden, we add an info note saying which versions
are safe, because we can't tell from outside whether the site is patched.

Linux distributions often backport security fixes without changing the
upstream version string (RHEL ships "PHP/8.2.13" with later patches applied).
When the server reports such a distribution, a version match is downgraded from
critical to high and the finding says to check the distribution's advisory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Category, Finding, Severity
from ..safety import UnsafeTargetError
from .base import ScanContext

Version = tuple[int, int, int]

#: Oldest PHP branch still receiving security fixes (8.1 ended 31 Dec 2025).
OLDEST_SUPPORTED = (8, 2)


@dataclass(frozen=True)
class Advisory:
    id: str
    name: str
    cves: tuple[str, ...]
    #: First fixed release per supported branch. Older branches have no fix.
    fixed: dict[tuple[int, int], Version]
    oldest_affected: Version
    summary: str
    interim: str
    references: tuple[str, ...]


ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        id="php2shell",
        name="PHP2Shell",
        cves=("CVE-2026-109618", "CVE-2026-109619"),
        fixed={(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)},
        oldest_affected=(5, 4, 0),
        summary=(
            "Two flaws in PHP's request handling (memory corruption and a use-after-free) let an "
            "unauthenticated attacker run code on the server with a crafted request, before your application "
            "code runs. Exploit code is circulating and attacks have been reported. Fixed on 21 October 2026."
        ),
        interim=(
            "If you can't upgrade immediately, set session.upload_progress.enabled = 0 in php.ini and restart "
            "every PHP worker. This only partly mitigates the issue; upgrading is the fix."
        ),
        references=(
            "https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/",
            "https://www.php.net/downloads.php",
        ),
    ),
)

_HEADER_VERSION = re.compile(r"\bPHP/(\d+)\.(\d+)\.(\d+)", re.I)
_PHPINFO_VERSION = re.compile(rb"PHP Version (\d+)\.(\d+)\.(\d+)")
_PHPINFO_UPLOAD_PROGRESS = re.compile(rb"session\.upload_progress\.enabled</td><td class=\"v\">(On|Off)", re.I)
_BACKPORTING_DISTROS = re.compile(r"red hat|rhel|centos|rocky|alma|debian|ubuntu|suse|amazon linux|oracle linux", re.I)
_PHP_HINTS = (
    (re.compile(r"PHPSESSID=", re.I), "a PHPSESSID session cookie"),
    (re.compile(r"""href=["'][^"']*\.php(?:[?"'#])""", re.I), "links to .php pages"),
    (re.compile(r"/wp-content/|/wp-includes/", re.I), "WordPress (which runs on PHP)"),
)
PHPINFO_PATHS = ("/phpinfo.php", "/info.php")


def branch_status(version: Version) -> tuple[list[Advisory], bool]:
    """Return (advisories this version is affected by, branch is end-of-life)."""
    branch = version[:2]
    eol = branch < OLDEST_SUPPORTED
    affected = []
    for adv in ADVISORIES:
        if version < adv.oldest_affected:
            continue
        fixed = adv.fixed.get(branch)
        if fixed is None:
            # Newer branches than the table knows about were released after the fix.
            if branch > max(adv.fixed):
                continue
            affected.append(adv)
        elif version < fixed:
            affected.append(adv)
    return affected, eol


def _fmt(v: Version) -> str:
    return ".".join(map(str, v))


def _fixed_list(adv: Advisory) -> str:
    return ", ".join(_fmt(v) for _, v in sorted(adv.fixed.items(), reverse=True))


class PhpVersionCheck:
    name = "php_version"
    title = "PHP version (known critical PHP vulnerabilities)"
    active = False

    async def run(self, ctx: ScanContext) -> list[Finding]:
        home = await ctx.homepage()
        headers = home.response.headers
        header_text = " ".join(f"{k}: {headers[k]}" for k in ("x-powered-by", "server") if k in headers)
        distro = bool(_BACKPORTING_DISTROS.search(headers.get("server", "")))

        version: Version | None = None
        source = ""
        upload_progress: str | None = None
        if m := _HEADER_VERSION.search(header_text):
            version = (int(m[1]), int(m[2]), int(m[3]))
            source = f"Response header: {header_text}"
        else:
            version, source, upload_progress = await self._from_phpinfo(ctx)

        if version is None:
            hint = self._php_hint(home.text, header_text, headers.get_list("set-cookie"))
            return [self._hidden_version_note(hint)] if hint else []

        evidence = source + (f"\nsession.upload_progress.enabled = {upload_progress}" if upload_progress else "")
        affected, eol = branch_status(version)
        out = [self._advisory_finding(version, adv, evidence, distro, eol) for adv in affected]
        if eol:
            out.append(self._eol_finding(version, evidence))
        return out

    @staticmethod
    async def _from_phpinfo(ctx: ScanContext) -> tuple[Version | None, str, str | None]:
        base = ctx.target.url.rstrip("/")
        for path in PHPINFO_PATHS:
            try:
                res = await ctx.fetcher.get(base + path, follow_redirects=False)
            except (UnsafeTargetError, OSError):
                continue
            if res.response.status_code != 200 or not (m := _PHPINFO_VERSION.search(res.body)):
                continue
            up = _PHPINFO_UPLOAD_PROGRESS.search(res.body)
            return (
                (int(m[1]), int(m[2]), int(m[3])),
                f"Exposed phpinfo() page at {path} reports PHP {m[1].decode()}.{m[2].decode()}.{m[3].decode()}",
                up[1].decode() if up else None,
            )
        return None, "", None

    @staticmethod
    def _php_hint(html: str, header_text: str, cookies: list[str]) -> str | None:
        if re.search(r"\bPHP\b", header_text, re.I):
            return f"the response headers ({header_text})"
        for rx, label in _PHP_HINTS:
            if any(rx.search(c) for c in cookies) or rx.search(html[:200_000]):
                return label
        return None

    @staticmethod
    def _advisory_finding(version: Version, adv: Advisory, evidence: str, distro: bool, eol: bool) -> Finding:
        branch = version[:2]
        fixed = adv.fixed.get(branch)
        if fixed:
            upgrade = f"Upgrade to PHP {_fmt(fixed)} or later (fixed releases: {_fixed_list(adv)})."
        else:
            upgrade = (
                f"PHP {branch[0]}.{branch[1]} is end-of-life and will not be fixed. Upgrade to a supported "
                f"branch: {_fixed_list(adv)} or later."
            )
        caveat = (
            " Your server reports a Linux distribution that may have backported the fix without changing the "
            "version number: check your distribution's security advisory before assuming you're safe."
            if distro and not eol
            else ""
        )
        return Finding(
            id=f"php.{adv.id}",
            title=f"PHP {_fmt(version)} is vulnerable to {adv.name} ({', '.join(adv.cves)})",
            severity=Severity.HIGH if distro and not eol else Severity.CRITICAL,
            category=Category.SOFTWARE,
            description=adv.summary + caveat,
            evidence=evidence,
            fix=f"{upgrade} Restart PHP-FPM/Apache afterwards so the new version is actually running. {adv.interim}",
            snippets={"php.ini (interim only)": "session.upload_progress.enabled = 0"},
            references=list(adv.references) + [f"https://www.cve.org/CVERecord?id={c}" for c in adv.cves],
        )

    @staticmethod
    def _eol_finding(version: Version, evidence: str) -> Finding:
        return Finding(
            id="php.eol",
            title=f"PHP {version[0]}.{version[1]} no longer gets security fixes",
            severity=Severity.HIGH,
            category=Category.SOFTWARE,
            description=(
                "This PHP branch is end-of-life. New vulnerabilities, including critical ones, are never fixed for it."
            ),
            evidence=evidence,
            fix=(
                f"Upgrade to PHP {OLDEST_SUPPORTED[0]}.{OLDEST_SUPPORTED[1]} or newer (8.4 or 8.5 give the longest "
                "support). Test your application and its plugins on the new version first."
            ),
            references=["https://www.php.net/supported-versions.php"],
        )

    @staticmethod
    def _hidden_version_note(hint: str) -> Finding:
        lines = "; ".join(f"{a.name}: {_fixed_list(a)} or later" for a in ADVISORIES)
        return Finding(
            id="php.version_unknown",
            title="This site runs PHP: make sure it's patched against PHP2Shell",
            severity=Severity.INFO,
            category=Category.SOFTWARE,
            description=(
                f"We detected PHP from {hint}, but the version is hidden (which is good), so we can't tell from "
                "outside whether it's patched against the critical October 2026 PHP flaws."
            ),
            fix=(
                f"On the server, run `php -v` (and check the version PHP-FPM reports). Safe versions: {lines}. "
                "PHP 8.1 and older get no fix."
            ),
            references=list(ADVISORIES[0].references),
        )
