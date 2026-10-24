from pathlib import Path

import pytest

from riskscope.disclosure import (
    DisclosureError,
    draft_email,
    group_recipients,
    parse_findings,
    registrable_domain,
    tracking_csv,
)
from riskscope.disclosure.__main__ import main

CSV = """host,issue,severity,recommendation,contact,org
shop.example.tn,No HTTPS redirect,medium,Redirect http to https,admin@example.tn,Example Shop
www.example.tn,Expired certificate,high,Renew the certificate,admin@example.tn,Example Shop
blog.other.tn,.git folder exposed,critical,Remove /.git,,Other Co
"""


def test_registrable_domain() -> None:
    assert registrable_domain("www.example.tn") == "example.tn"
    assert registrable_domain("a.b.shop.example.com.tn") == "example.com.tn"  # two-label suffix
    assert registrable_domain("example.com") == "example.com"
    assert registrable_domain("host.co.uk") == "host.co.uk"


def test_parse_and_group() -> None:
    findings = parse_findings(CSV)
    assert len(findings) == 3
    recipients = group_recipients(findings)
    assert len(recipients) == 2
    by_key = {r.key: r for r in recipients}
    # Two findings share a contact -> one recipient; the third has no contact -> grouped by domain.
    assert set(by_key["admin@example.tn"].hosts) == {"shop.example.tn", "www.example.tn"}
    assert by_key["admin@example.tn"].has_contact
    assert not by_key["other.tn"].has_contact


def test_parse_flexible_headers_and_errors() -> None:
    assert len(parse_findings("domain,finding\nx.tn,bad thing\n")) == 1
    with pytest.raises(DisclosureError, match="host and an issue"):
        parse_findings("foo,bar\n1,2\n")
    with pytest.raises(DisclosureError):
        parse_findings("")
    with pytest.raises(DisclosureError, match="No usable rows"):
        parse_findings("host,issue\n,\n")


def test_draft_email_is_polite_and_non_coercive() -> None:
    [r] = [x for x in group_recipients(parse_findings(CSV)) if x.has_contact]
    email = draft_email(
        r,
        sender_name="Jane Doe",
        source="Censys public data",
        self_check_url="https://riskscope.example/",
        cert_name="ANSI / tunCERT",
        cert_contact="contact@ansi.tn",
        today="2026-10-24",
    )
    assert email.to == "admin@example.tn"
    assert "Security issues on example.tn (high)" == email.subject
    assert "have not attempted to access or exploit" in email.body
    assert "shop.example.tn: No HTTPS redirect" in email.body
    assert "Censys public data" in email.body
    assert "https://riskscope.example/" in email.body
    assert "ANSI / tunCERT (contact@ansi.tn)" in email.body
    # No threats, deadlines, or payment — coordinated disclosure, not extortion.
    for bad in ("bitcoin", "payment", "deadline", "or else", "leak"):
        assert bad not in email.body.lower()


def test_no_contact_email_has_placeholder() -> None:
    [r] = [x for x in group_recipients(parse_findings(CSV)) if not x.has_contact]
    email = draft_email(r, sender_name="Jane", source="public data")
    assert "no contact found" in email.to and "other.tn" in email.to


def test_tracking_csv() -> None:
    rows = tracking_csv(group_recipients(parse_findings(CSV))).strip().splitlines()
    assert rows[0].startswith("recipient,organisation,has_contact")
    assert any("admin@example.tn" in r and "yes" in r for r in rows)
    assert any("other.tn" in r and ",no," in r for r in rows)


def test_cli_writes_drafts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = tmp_path / "in.csv"
    src.write_text(CSV, encoding="utf-8")
    out = tmp_path / "drafts"
    rc = main([str(src), "--from", "Jane Doe", "--out", str(out), "--self-check-url", "https://rs.example/"])
    assert rc == 0
    files = sorted(p.name for p in out.iterdir())
    assert "tracking.csv" in files and any(f.endswith(".txt") for f in files)
    body = (out / "admin@example.tn.txt").read_text()
    assert body.startswith("To: admin@example.tn") and "Subject: Security issues on example.tn" in body
    assert "nothing was sent" in capsys.readouterr().out


def test_cli_bad_csv(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = tmp_path / "bad.csv"
    src.write_text("a,b\n1,2\n", encoding="utf-8")
    assert main([str(src), "--from", "x", "--out", str(tmp_path / "o")]) == 1
    assert "error:" in capsys.readouterr().err
