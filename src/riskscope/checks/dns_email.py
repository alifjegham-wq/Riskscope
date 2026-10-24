"""Email spoofing protection (SPF, DMARC) and DNS hardening (CAA, DNSSEC)."""

from __future__ import annotations

from ..models import Category, Finding, Severity
from .base import ScanContext


class EmailAuthCheck:
    name = "email_auth"
    title = "Email spoofing protection (SPF & DMARC)"
    active = False

    async def run(self, ctx: ScanContext) -> list[Finding]:
        domain = ctx.target.registrable_hint
        out: list[Finding] = []

        spf = [t for t in await ctx.dns(domain, "TXT") if t.lower().startswith("v=spf1")]
        if not spf:
            out.append(
                Finding(
                    id="email.spf.missing",
                    title="No SPF record",
                    severity=Severity.MEDIUM,
                    category=Category.EMAIL,
                    description="Anyone can send email that claims to come from your domain.",
                    fix=(
                        "Publish an SPF TXT record listing who sends your mail. If the domain never sends "
                        "mail, publish 'v=spf1 -all'."
                    ),
                    snippets={"DNS TXT @": "v=spf1 include:_spf.google.com -all   (adjust to your mail provider)"},
                )
            )
        elif len(spf) > 1:
            out.append(
                Finding(
                    id="email.spf.multiple",
                    title="More than one SPF record",
                    severity=Severity.MEDIUM,
                    category=Category.EMAIL,
                    description="Multiple SPF records make SPF fail entirely (RFC 7208 §4.5).",
                    evidence=" | ".join(spf),
                    fix="Merge them into a single v=spf1 record.",
                )
            )
        elif spf[0].rstrip().endswith(("+all", "?all")):
            out.append(
                Finding(
                    id="email.spf.permissive",
                    title="SPF record allows any sender",
                    severity=Severity.MEDIUM,
                    category=Category.EMAIL,
                    description="'+all' or '?all' means the SPF record gives no protection.",
                    evidence=spf[0],
                    fix="End the record with '-all' (or '~all' while testing).",
                )
            )

        dmarc = [t for t in await ctx.dns(f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
        if not dmarc:
            out.append(
                Finding(
                    id="email.dmarc.missing",
                    title="No DMARC policy",
                    severity=Severity.MEDIUM,
                    category=Category.EMAIL,
                    description=(
                        "DMARC tells receiving mail servers to reject forged mail from your domain. "
                        "It is the main defence against phishing that impersonates you."
                    ),
                    fix="Start with p=none and a report address, review reports, then move to quarantine/reject.",
                    snippets={"DNS TXT _dmarc": f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}"},
                    references=["https://dmarc.org/overview/"],
                )
            )
        else:
            tags = _tags(dmarc[0])
            if tags.get("p", "none") == "none":
                out.append(
                    Finding(
                        id="email.dmarc.monitor_only",
                        title="DMARC is in monitor-only mode (p=none)",
                        severity=Severity.LOW,
                        category=Category.EMAIL,
                        description="Forged mail is reported but still delivered.",
                        evidence=dmarc[0],
                        fix="Once reports look clean, move to p=quarantine and then p=reject.",
                    )
                )
        return out


class DnsHardeningCheck:
    name = "dns_hardening"
    title = "DNS hardening (CAA, DNSSEC)"
    active = False

    async def run(self, ctx: ScanContext) -> list[Finding]:
        domain = ctx.target.registrable_hint
        out: list[Finding] = []
        if not await ctx.dns(domain, "CAA"):
            out.append(
                Finding(
                    id="dns.caa.missing",
                    title="No CAA record",
                    severity=Severity.LOW,
                    category=Category.EMAIL,
                    description="Any certificate authority may issue certificates for your domain.",
                    fix="Publish CAA records naming the CA(s) you actually use.",
                    snippets={"DNS CAA @": '0 issue "letsencrypt.org"'},
                )
            )
        if not await ctx.dns(domain, "DS"):
            out.append(
                Finding(
                    id="dns.dnssec.missing",
                    title="DNSSEC is not enabled",
                    severity=Severity.INFO,
                    category=Category.EMAIL,
                    description="DNSSEC protects visitors from forged DNS answers; most registrars offer it.",
                    fix="Enable DNSSEC at your DNS provider and registrar.",
                )
            )
        return out


def _tags(record: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in record.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            out[k.strip().lower()] = v.strip().lower()
    return out
