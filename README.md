# riskscope

**Free, open-source security scanner for websites and applications.** Enter a domain or upload your code and get
a risk grade (A–F), a risk level, and a list of what to fix, most urgent first. Each fix comes with config you
can paste for nginx, Apache, DNS and so on.

It is built for people who don't have a security team: small businesses, freelancers, non-profits, solo developers.

## What it checks

### Websites: passive (anyone can run these on any public site)

| Area | Checks |
|---|---|
| Encryption (TLS) | Certificate trust and expiry, TLS 1.0/1.1 still accepted, HTTP → HTTPS redirect |
| Browser protections | HSTS, Content-Security-Policy (incl. `unsafe-inline`), clickjacking, `nosniff`, Referrer-Policy, Permissions-Policy, CORS origin reflection |
| Cookies | `Secure`, `HttpOnly`, `SameSite`, rated higher for session cookies |
| Email & DNS | SPF (missing / multiple / `+all`), DMARC (missing / `p=none`), CAA, DNSSEC |
| Exposed files | `.git`, `.env`, AWS credentials, SQL dumps, config backups, `.htpasswd`, backup archives, `server-status`, `phpinfo`, `.DS_Store`, directory listing, `security.txt` |
| Outdated software | Version disclosure in headers; front-end JS libraries (jQuery, Bootstrap, Angular, Lodash, …) checked against [OSV.dev](https://osv.dev) |

Exposed-file checks match file *contents* (e.g. `ref: refs/` for `.git/HEAD`), so sites that answer
"200 OK" for every URL don't produce false positives.

### Websites: active (only after you prove you own the domain)

| Area | Checks |
|---|---|
| Network services | TCP connect to risky ports: Redis, MongoDB, Elasticsearch, Docker API, RDP, SMB, databases, Telnet, VNC, … |

To verify ownership, publish a TXT record at `_riskscope-challenge.<domain>` or serve a file at
`/.well-known/riskscope-verify.txt`. Tokens are an HMAC of the domain, so the server keeps no state.

### Application code (upload files or a .zip)

* **Vulnerable dependencies** from lockfiles: `package-lock.json`, `yarn.lock`, `poetry.lock`, `uv.lock`,
  `Pipfile.lock`, `requirements*.txt` (pinned), `go.mod`, `composer.lock`, `Gemfile.lock`, `Cargo.lock`,
  looked up on OSV.dev with severity and the version to upgrade to.
* **Hard-coded secrets**: AWS keys, private keys, GitHub/Slack/Stripe/Google/Anthropic/OpenAI keys, database URLs
  with passwords. Matches are masked in the report.

Uploads are processed in memory and never stored. Only package names and versions leave the server (to OSV.dev).

## Scoring

Start at 100 and subtract per finding: critical 40, high 20, medium 8, low 3, info 0. A second finding in the same
category counts half and any further ones a quarter, so one noisy area can't dominate. Any critical finding caps the
score at 49 (F). Grades: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50. The full explanation is on the `/how-it-works` page.

## Running it

```bash
uv sync
uv run uvicorn riskscope.web.app:create_app --factory --reload
# open http://127.0.0.1:8000
```

JSON API (interactive docs at `/api/docs`):

```bash
curl 'http://127.0.0.1:8000/api/scan?target=example.com'
curl 'http://127.0.0.1:8000/api/scan?target=example.com&deep=true'   # needs ownership verification
curl -F files=@package-lock.json -F files=@settings.py http://127.0.0.1:8000/api/code
```

### Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `RISKSCOPE_VERIFY_SECRET` | random per process | HMAC key for ownership tokens. **Set it in production**, otherwise tokens change on restart |
| `RISKSCOPE_SCANS_PER_HOUR` | 20 | Scans per client IP per hour |
| `RISKSCOPE_MAX_UPLOAD_MB` | 20 | Upload size limit |
| `RISKSCOPE_TRUST_PROXY` | false | Take the client IP from `X-Forwarded-For` (only behind your own proxy) |

## Deploying

```bash
docker build -t riskscope .
docker run -p 8000:8000 -e RISKSCOPE_VERIFY_SECRET=$(openssl rand -hex 32) riskscope
```

A public scanner fetches URLs that strangers give it, so it's a natural SSRF target. riskscope accepts only public
hostnames, checks that every resolved address is globally routable, re-validates every redirect hop, and connects
TLS and port probes to the IP it already validated. **Also enforce this at the network layer**: run the container
with egress that blocks RFC 1918, link-local (169.254.0.0/16, including cloud metadata), loopback and your
internal ranges. That closes the remaining DNS-rebinding window between our check and the HTTP client's own
lookup.

The rate limiter is in memory, so it only works for a single process. Put a shared limiter (e.g. Redis) or your
CDN's rate limiting in front before scaling out.

## Development

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy src tests && uv run pytest -q
```

Each website check is a class with `name`, `title`, `active` and `async run(ctx) -> list[Finding]`
(`src/riskscope/checks/`). Register new checks in `checks/__init__.py`. Every finding needs a plain-language
`description`, a concrete `fix`, and snippets where config solves it. All network access goes through
`ScanContext` (`fetcher`, `dns`), which tests replace with fakes, so the test suite never touches the internet.

## Roadmap

- [ ] Background job queue and shareable report links (opt-in, expiring)
- [ ] Scheduled re-scans with email alerts on grade drops or certificate expiry
- [ ] Subdomain discovery from certificate transparency, plus dangling-CNAME (subdomain takeover) detection
- [ ] More active checks for verified owners: open redirects, reflected XSS canaries, admin panel default credentials
- [ ] Static analysis (SAST) of uploaded code; `pnpm-lock.yaml`, Maven/Gradle lockfiles
- [ ] Dependency-file scanning straight from a public GitHub repo URL
- [ ] PDF / shareable report export for compliance evidence

## Responsible use

Only scan websites and code that you own or are explicitly authorised to test. Passive checks behave like an
ordinary visitor or search engine; active checks are gated behind proof of ownership for that reason.
Report vulnerabilities in riskscope itself per [SECURITY.md](SECURITY.md).

## Licence

[AGPL-3.0-only](LICENSE). You're free to use, modify and host riskscope. If you run a modified version as a service,
you must publish your changes.
