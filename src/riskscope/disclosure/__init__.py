"""Coordinated-disclosure helper: turn lawfully-obtained exposure data into notifications.

This module does **no scanning**. It reads a CSV of findings you already have — for
example exported from a public internet-scan dataset such as Shodan, Censys or Rapid7
Open Data, or produced by scanning systems you are authorised to test — and drafts
polite coordinated-disclosure emails grouped by recipient, plus a tracking sheet.

The point is to help organisations fix problems without you generating any scanning
traffic against systems you don't own. See docs/DISCLOSURE.md.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import UTC, datetime

# Accepted CSV column names (case-insensitive), mapped to our fields.
_COLUMNS = {
    "host": {"host", "hostname", "domain", "target", "ip", "address"},
    "issue": {"issue", "finding", "problem", "vulnerability", "title"},
    "severity": {"severity", "risk", "level"},
    "detail": {"detail", "details", "description", "evidence", "notes"},
    "fix": {"fix", "recommendation", "remediation", "solution"},
    "contact": {"contact", "email", "security_contact", "abuse_contact", "to"},
    "org": {"org", "organisation", "organization", "owner", "company"},
}


class DisclosureError(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    host: str
    issue: str
    severity: str = ""
    detail: str = ""
    fix: str = ""
    contact: str = ""
    org: str = ""


@dataclass
class Recipient:
    """Everything owed to one notification target (grouped by contact, else by domain)."""

    key: str  # contact email, or the grouping domain when no contact is known
    contact: str
    org: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def hosts(self) -> list[str]:
        return sorted({f.host for f in self.findings})

    @property
    def has_contact(self) -> bool:
        return bool(self.contact)


def registrable_domain(host: str) -> str:
    """Rough registrable-domain guess for grouping (not a public-suffix-list lookup)."""
    host = host.strip().strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Treat common two-label public suffixes (e.g. com.tn, co.uk) as part of the suffix.
    two_label = {"com", "co", "net", "org", "gov", "edu", "ac"}
    if parts[-2] in two_label and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _norm_header(fieldnames: list[str]) -> dict[str, str]:
    """Map the CSV's actual headers onto our field names."""
    mapping: dict[str, str] = {}
    for raw in fieldnames:
        key = raw.strip().lower()
        for field_name, aliases in _COLUMNS.items():
            if key in aliases and field_name not in mapping.values():
                mapping[raw] = field_name
                break
    return mapping


def parse_findings(csv_text: str) -> list[Finding]:
    reader = csv.DictReader(io.StringIO(csv_text))
    if not reader.fieldnames:
        raise DisclosureError("The CSV is empty or has no header row")
    mapping = _norm_header(list(reader.fieldnames))
    have = set(mapping.values())
    missing = {"host", "issue"} - have
    if missing:
        raise DisclosureError(
            f"The CSV needs at least a host and an issue column (missing: {', '.join(sorted(missing))}). "
            f"Recognised headers: {', '.join(sorted(mapping.keys())) or 'none'}"
        )
    findings: list[Finding] = []
    for row in reader:
        values = {our: (row.get(orig) or "").strip() for orig, our in mapping.items()}
        host, issue = values.get("host", ""), values.get("issue", "")
        if not host or not issue:
            continue
        findings.append(
            Finding(
                host=host.lower(),
                issue=issue,
                severity=values.get("severity", ""),
                detail=values.get("detail", ""),
                fix=values.get("fix", ""),
                contact=values.get("contact", "").lower(),
                org=values.get("org", ""),
            )
        )
    if not findings:
        raise DisclosureError("No usable rows found (each row needs a host and an issue)")
    return findings


def group_recipients(findings: list[Finding]) -> list[Recipient]:
    buckets: dict[str, Recipient] = {}
    for f in findings:
        key = f.contact or registrable_domain(f.host)
        if key not in buckets:
            buckets[key] = Recipient(key=key, contact=f.contact, org=f.org)
        r = buckets[key]
        r.findings.append(f)
        if not r.contact and f.contact:
            r.contact = f.contact
        if not r.org and f.org:
            r.org = f.org
    return [buckets[k] for k in sorted(buckets)]


def _finding_line(f: Finding) -> str:
    bits = [f"- {f.host}: {f.issue}"]
    if f.severity:
        bits.append(f"[{f.severity}]")
    line = " ".join(bits)
    if f.detail:
        line += f"\n    {f.detail}"
    if f.fix:
        line += f"\n    Suggested fix: {f.fix}"
    return line


@dataclass(frozen=True)
class DraftEmail:
    to: str  # a real address, or a "(no contact found ...)" placeholder
    subject: str
    body: str


def draft_email(
    recipient: Recipient,
    *,
    sender_name: str,
    source: str,
    self_check_url: str = "",
    cert_name: str = "",
    cert_contact: str = "",
    today: str = "",
) -> DraftEmail:
    today = today or datetime.now(UTC).strftime("%Y-%m-%d")
    domain = registrable_domain(recipient.hosts[0])
    org = recipient.org or domain
    to = recipient.contact or f"(no contact found — look up the security/abuse contact for {domain})"

    lead = (
        f"Hello,\n\n"
        f"My name is {sender_name}. I came across a few security issues affecting {org} "
        f"while reviewing {source}. I'm writing to let you know so they can be fixed — I have not "
        f"attempted to access or exploit anything, and this is sent only to help.\n\n"
        f"Affected:\n"
    )
    body = lead + "\n".join(_finding_line(f) for f in recipient.findings)
    if self_check_url:
        body += f"\n\nYou can re-check any of these yourself here: {self_check_url}"
    body += (
        "\n\nThere is no cost and nothing is expected in return. If you'd like help understanding any of "
        "these, just reply.\n"
    )
    if cert_name:
        contact = f" ({cert_contact})" if cert_contact else ""
        body += f"\nIf you'd prefer, your national CERT {cert_name}{contact} can also advise.\n"
    body += f"\nKind regards,\n{sender_name}\n{today}\n"

    worst = _most_severe(recipient.findings)
    subject = f"Security issues on {domain}" + (f" ({worst})" if worst else "")
    return DraftEmail(to=to, subject=subject, body=body)


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _most_severe(findings: list[Finding]) -> str:
    present = {f.severity.lower() for f in findings if f.severity}
    for level in _SEVERITY_ORDER:
        if level in present:
            return level
    return ""


def tracking_csv(recipients: list[Recipient]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["recipient", "organisation", "has_contact", "hosts", "findings", "worst_severity", "status"])
    for r in recipients:
        writer.writerow(
            [
                r.contact or registrable_domain(r.hosts[0]),
                r.org,
                "yes" if r.has_contact else "no",
                len(r.hosts),
                len(r.findings),
                _most_severe(r.findings),
                "draft",
            ]
        )
    return out.getvalue()


__all__ = [
    "DisclosureError",
    "DraftEmail",
    "Finding",
    "Recipient",
    "draft_email",
    "group_recipients",
    "parse_findings",
    "registrable_domain",
    "tracking_csv",
]
