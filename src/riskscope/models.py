"""Core data types shared by every check, the scorer and the web layer."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Category(StrEnum):
    TLS = "Encryption (TLS)"
    HEADERS = "Browser protections"
    COOKIES = "Cookies"
    EMAIL = "Email & DNS"
    EXPOSURE = "Exposed files"
    SOFTWARE = "Outdated software"
    NETWORK = "Network services"
    DEPENDENCIES = "Dependencies"
    SECRETS = "Secrets in code"


class Finding(BaseModel):
    """One problem (or confirmation) with evidence and a concrete fix."""

    id: str = Field(description="Stable identifier, e.g. 'headers.hsts.missing'")
    title: str
    severity: Severity
    category: Category
    description: str = Field(description="Why this matters, in plain language")
    evidence: str = ""
    fix: str = Field(default="", description="What to do about it")
    snippets: dict[str, str] = Field(default_factory=dict, description="Platform name -> config to paste")
    references: list[str] = Field(default_factory=list)


class CheckError(BaseModel):
    check: str
    message: str


class Report(BaseModel):
    target: str
    kind: str = Field(description="'website' or 'code'")
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int = 0
    findings: list[Finding] = Field(default_factory=list)
    passed: list[str] = Field(default_factory=list, description="Titles of checks that found nothing wrong")
    errors: list[CheckError] = Field(default_factory=list)
    score: int = 100
    grade: str = "A"
    risk_level: str = "Low"
    verified_owner: bool = False

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.category, f.id))

    def counts(self) -> dict[Severity, int]:
        out = dict.fromkeys(Severity, 0)
        for f in self.findings:
            out[f.severity] += 1
        return out
