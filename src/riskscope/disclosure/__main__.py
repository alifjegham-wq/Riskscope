"""CLI: riskscope-disclose — draft coordinated-disclosure emails from a findings CSV (no scanning).

    uv run python -m riskscope.disclosure findings.csv --from "Jane Doe <jane@example.org>" --out drafts/

Reads a CSV (needs at least host and issue columns; also understands severity, detail, fix,
contact, org), groups by security contact (or domain when none is given), writes one email
draft per recipient plus tracking.csv into the output directory.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import DisclosureError, draft_email, group_recipients, parse_findings, tracking_csv


def _safe_name(key: str) -> str:
    return "".join(c if c.isalnum() or c in "-._@" else "_" for c in key)[:80] or "recipient"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="riskscope-disclose", description=__doc__)
    parser.add_argument("csv", type=Path, help="Findings CSV (lawfully obtained; no scanning is performed)")
    parser.add_argument("--from", dest="sender", required=True, help='Your name, e.g. "Jane Doe <jane@example.org>"')
    parser.add_argument("--out", type=Path, default=Path("drafts"), help="Output directory (default: drafts/)")
    parser.add_argument(
        "--source",
        default="publicly available internet-scan data",
        help="How you obtained the findings, named in each email",
    )
    parser.add_argument("--self-check-url", default="", help="riskscope URL recipients can use to re-check")
    parser.add_argument("--cert-name", default="", help="National CERT to mention, e.g. 'ANSI / tunCERT'")
    parser.add_argument("--cert-contact", default="", help="National CERT contact, e.g. contact@ansi.tn")
    args = parser.parse_args(argv)

    try:
        findings = parse_findings(args.csv.read_text(encoding="utf-8"))
    except (OSError, DisclosureError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    recipients = group_recipients(findings)
    args.out.mkdir(parents=True, exist_ok=True)
    for r in recipients:
        email = draft_email(
            r,
            sender_name=args.sender,
            source=args.source,
            self_check_url=args.self_check_url,
            cert_name=args.cert_name,
            cert_contact=args.cert_contact,
        )
        text = f"To: {email.to}\nSubject: {email.subject}\n\n{email.body}"
        (args.out / f"{_safe_name(r.key)}.txt").write_text(text, encoding="utf-8")
    (args.out / "tracking.csv").write_text(tracking_csv(recipients), encoding="utf-8")

    with_contact = sum(1 for r in recipients if r.has_contact)
    print(
        f"Drafted {len(recipients)} email(s) for {len(findings)} finding(s) in {args.out}/ "
        f"({with_contact} have a contact address; the rest need one looked up). "
        f"Review each draft before sending — nothing was sent."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
