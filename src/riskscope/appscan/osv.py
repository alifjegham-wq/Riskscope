"""Known-vulnerability lookups against OSV.dev (free, no API key)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from ..models import Category, Finding, Severity

OSV_API = "https://api.osv.dev/v1"
MAX_DETAIL_LOOKUPS = 60
_BATCH = 500


@dataclass(frozen=True)
class Package:
    ecosystem: str  # OSV ecosystem name: npm, PyPI, Go, Packagist, RubyGems, crates.io, Maven
    name: str
    version: str
    source: str = ""  # file it came from, for the report


@dataclass
class Vuln:
    id: str
    summary: str
    severity: Severity
    fixed: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)


class VulnSource(Protocol):
    async def lookup(self, packages: list[Package]) -> dict[Package, list[Vuln]]: ...


_GHSA_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def parse_vuln(data: dict[str, Any], package: Package) -> Vuln:
    sev_label = str((data.get("database_specific") or {}).get("severity", "")).upper()
    severity = _GHSA_SEVERITY.get(sev_label, Severity.MEDIUM)
    fixed: list[str] = []
    for affected in data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != package.name.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed.append(str(event["fixed"]))
    return Vuln(
        id=str(data.get("id", "")),
        summary=str(data.get("summary") or data.get("details", "")[:160] or "Known vulnerability"),
        severity=severity,
        fixed=sorted(set(fixed)),
        aliases=[str(a) for a in data.get("aliases", [])],
    )


class OsvClient:
    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self.client = client or httpx.AsyncClient(timeout=20.0)

    async def lookup(self, packages: list[Package]) -> dict[Package, list[Vuln]]:
        packages = list(dict.fromkeys(packages))
        hits: dict[Package, list[str]] = {}
        for i in range(0, len(packages), _BATCH):
            chunk = packages[i : i + _BATCH]
            queries = [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version} for p in chunk]
            resp = await self.client.post(f"{OSV_API}/querybatch", json={"queries": queries})
            resp.raise_for_status()
            for pkg, result in zip(chunk, resp.json().get("results", []), strict=False):
                ids = [v["id"] for v in (result or {}).get("vulns", [])]
                if ids:
                    hits[pkg] = ids

        unique_ids = list(dict.fromkeys(i for ids in hits.values() for i in ids))[:MAX_DETAIL_LOOKUPS]
        sem = asyncio.Semaphore(8)

        async def detail(vid: str) -> tuple[str, dict[str, Any] | None]:
            async with sem:
                r = await self.client.get(f"{OSV_API}/vulns/{vid}")
            return vid, (r.json() if r.status_code == 200 else None)

        details = dict(await asyncio.gather(*(detail(v) for v in unique_ids)))
        out: dict[Package, list[Vuln]] = {}
        for pkg, ids in hits.items():
            vulns = []
            for vid in ids:
                data = details.get(vid)
                vulns.append(
                    parse_vuln(data, pkg)
                    if data
                    else Vuln(id=vid, summary="Known vulnerability", severity=Severity.MEDIUM)
                )
            out[pkg] = vulns
        return out


def findings_for(results: dict[Package, list[Vuln]], category: Category) -> list[Finding]:
    """One finding per vulnerable package, rated by its worst vulnerability."""
    out: list[Finding] = []
    for pkg, vulns in sorted(results.items(), key=lambda kv: (kv[0].name, kv[0].version)):
        worst = min(vulns, key=lambda v: v.severity.rank)
        fixed = sorted({f for v in vulns for f in v.fixed}, key=_version_key)
        noun = "vulnerability" if len(vulns) == 1 else "vulnerabilities"
        listing = "\n".join(_describe(v) for v in sorted(vulns, key=lambda v: v.severity.rank))
        out.append(
            Finding(
                id=f"vuln.{pkg.ecosystem}.{pkg.name}@{pkg.version}",
                title=f"{pkg.name} {pkg.version} has {len(vulns)} known {noun}",
                severity=worst.severity,
                category=category,
                description=f"{pkg.ecosystem} package" + (f" from {pkg.source}" if pkg.source else "") + ".",
                evidence=listing,
                fix=(
                    f"Upgrade {pkg.name} to {fixed[-1]} or later (the newest fix among these advisories)."
                    if fixed
                    else f"No fixed release is listed yet; replace {pkg.name} or apply the advisories' mitigations."
                ),
                references=[f"https://osv.dev/vulnerability/{v.id}" for v in vulns[:5]],
            )
        )
    return out


def _describe(v: Vuln) -> str:
    cves = [a for a in v.aliases if a.startswith("CVE-")]
    label = f"{v.id} ({', '.join(cves)})" if cves else v.id
    return f"[{v.severity}] {label}: {v.summary}"


def _version_key(v: str) -> tuple[tuple[int, int | str], ...]:
    parts: list[tuple[int, int | str]] = []
    for piece in v.replace("-", ".").split("."):
        parts.append((0, int(piece)) if piece.isdigit() else (1, piece))
    return tuple(parts)
