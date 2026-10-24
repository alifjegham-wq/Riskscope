"""Hard-coded credentials in source files. Matches are masked before they reach the report."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Category, Finding, Severity


@dataclass(frozen=True)
class SecretRule:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity = Severity.CRITICAL


RULES: tuple[SecretRule, ...] = (
    SecretRule("aws_access_key", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    SecretRule(
        "private_key",
        "Private key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    ),
    SecretRule(
        "github_token",
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    ),
    SecretRule("slack_token", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    SecretRule("stripe_live_key", "Stripe live secret key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b")),
    SecretRule("google_api_key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.HIGH),
    SecretRule("anthropic_key", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    SecretRule("openai_key", "OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b"), Severity.HIGH),
    SecretRule(
        "db_url_password",
        "Database URL with password",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s/@]+:[^@\s/]{3,}@[^\s'\"]+"),
        Severity.HIGH,
    ),
)

MAX_FILE_BYTES = 1_000_000


def mask(secret: str) -> str:
    if len(secret) <= 10:
        return secret[:2] + "…"
    return f"{secret[:6]}…{secret[-2:]} ({len(secret)} chars)"


def find_secrets(filename: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    for rule in RULES:
        hits: list[str] = []
        for m in rule.pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            hits.append(f"{filename}:{line}  {mask(m.group(0))}")
        if hits:
            out.append(
                Finding(
                    id=f"secrets.{rule.id}.{filename}",
                    title=f"{rule.name} committed in {filename}",
                    severity=rule.severity,
                    category=Category.SECRETS,
                    description=(
                        "Anything in source code ends up in backups, CI logs, forks and every developer laptop. "
                        "Assume this credential is already compromised."
                    ),
                    evidence="\n".join(hits[:10]) + (f"\n… and {len(hits) - 10} more" if len(hits) > 10 else ""),
                    fix=(
                        "1) Revoke/rotate the credential now. 2) Load it from an environment variable or secrets "
                        "manager instead. 3) Purge it from git history (git filter-repo) and add a pre-commit "
                        "secret scanner."
                    ),
                )
            )
    return out
