# Coordinated disclosure helper

When you find that organisations you don't control have security problems, the lawful way to help is
**coordinated disclosure**: tell the owner (or their national CERT), without generating scanning traffic
against systems you aren't authorised to test.

`riskscope-disclose` helps with the last step. It does **no scanning**. You bring the findings — exported
from a public internet-scan dataset such as [Shodan](https://www.shodan.io),
[Censys](https://censys.io) or [Rapid7 Open Data](https://opendata.rapid7.com), or produced by scanning
systems you are authorised to test — and it drafts polite notification emails grouped by recipient.

## Input

A CSV. It needs at least a **host** and an **issue** column; it also understands **severity**, **detail**,
**fix**, **contact** and **org** (header names are flexible — `domain`, `finding`, `email`, etc. are
recognised). Example:

```csv
host,issue,severity,recommendation,contact,org
shop.example.tn,No HTTPS redirect,medium,Redirect http to https,admin@example.tn,Example Shop
blog.other.tn,.git folder exposed,critical,Remove /.git,,Other Co
```

## Run it

```bash
uv run riskscope-disclose findings.csv \
  --from "Jane Doe <jane@example.org>" \
  --source "Censys public data" \
  --self-check-url https://your-riskscope.example/ \
  --cert-name "ANSI / tunCERT" --cert-contact contact@ansi.tn \
  --out drafts/
```

This writes one email draft per recipient into `drafts/`, plus `tracking.csv`. Rows are grouped by security
contact; where no contact is known, they're grouped by domain and the draft tells you to look one up (try the
domain's `security.txt`, WHOIS/RDAP abuse contact, or the national CERT).

## Rules of the road

- **Review every draft before sending.** Nothing is sent for you.
- Say who you are, how you found the issue, and that you did not access or exploit anything.
- No demands, deadlines, or payment — that's extortion, not disclosure.
- If an owner asks you to stop, stop.
- When in doubt, route it through the national CERT (in Tunisia, [ANSI / tunCERT](https://www.ansi.tn)).
