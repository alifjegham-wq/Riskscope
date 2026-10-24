# riskscope

**Free, open-source security scanner for websites and applications.** Enter a domain or upload your code and get
a risk grade (A–F), a risk level, and a list of what to fix, most urgent first. Each fix comes with config you
can paste for nginx, Apache, DNS and so on.

It is built for people who don't have a security team: small businesses, freelancers, non-profits, solo developers.

## What it checks

### Websites: passive (anyone can run these on any public site)

| Area | Checks |
|---|---|
| By IP / CIDR | Enter an IP address or a small CIDR block and riskscope finds the site(s) hosted there (reverse DNS, TLS certificate names, optional passive DNS) and runs the passive checks below on each |
| Encryption (TLS) | Certificate trust and expiry, TLS 1.0/1.1 still accepted, HTTP → HTTPS redirect |
| Browser protections | HSTS, Content-Security-Policy (incl. `unsafe-inline`), clickjacking, `nosniff`, Referrer-Policy, Permissions-Policy, CORS origin reflection |
| Cookies | `Secure`, `HttpOnly`, `SameSite`, rated higher for session cookies |
| Email & DNS | SPF (missing / multiple / `+all`), DMARC (missing / `p=none`), CAA, DNSSEC |
| Exposed files | `.git`, `.env`, AWS credentials, SQL dumps, config backups, `.htpasswd`, backup archives, `server-status`, `phpinfo`, `.DS_Store`, directory listing, `security.txt` |
| Subdomains | Subdomain takeover: subdomains (from certificate transparency logs plus common names) whose CNAME points at an unclaimed GitHub Pages, Heroku, S3, Azure, Shopify, Fastly, … resource, and dangling CNAMEs to names that no longer exist |
| PHP runtime | PHP version (from headers or an exposed `phpinfo()`) checked against critical PHP advisories, currently **PHP2Shell** (CVE-2026-109618/-109619, fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35), plus end-of-life branches. Hidden versions get an info note listing the safe releases |
| Outdated software | Version disclosure in headers; front-end JS libraries (jQuery, Bootstrap, Angular, Lodash, …) checked against [OSV.dev](https://osv.dev) |

Subdomain takeover detection only flags a service when there's evidence the resource is unclaimed: either the
service's own "nothing here" page (fingerprints based on
[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)) or, for providers where that is enough,
the CNAME target no longer existing in DNS. DNS timeouts are never counted as "doesn't exist". It costs only DNS
lookups plus one homepage request for subdomains that point at a known service. The scanned domain name is sent to
[crt.sh](https://crt.sh) to look up certificate transparency logs.

PHP advisories are a data table in `src/riskscope/checks/php.py` (`ADVISORIES`, `OLDEST_SUPPORTED`). When PHP
ships the next emergency release, add an entry there. Because distributions backport fixes without changing the
version string, a vulnerable-looking version on a server that reports RHEL, Debian, Ubuntu and similar is
rated high (with a "check your distribution's advisory" note) rather than critical.

### Scanning by IP or CIDR

Enter an IP (e.g. `1.1.1.1`) or a small block (e.g. `1.1.1.0/30`) instead of a domain. riskscope finds the
hostnames served there from reverse DNS (PTR), the names on the TLS certificate on port 443, and, if a
provider is configured, passive DNS, then runs the passive website checks on each. Only public, globally
routable addresses are accepted; blocks larger than `RISKSCOPE_MAX_CIDR_HOSTS` are refused. Every discovered
hostname is forward-confirmed (it must itself resolve to a public address) before it is scanned, so a crafted
PTR or certificate can't redirect the scanner inward. Active port checks are never run this way — they still
need per-domain ownership verification.

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

### Shareable reports (opt-in)

Tick **Create a shareable link** (or pass `share=true` to the API) and the report is saved behind an
unguessable link (`/r/<id>`, 128-bit id) that expires after `RISKSCOPE_SHARE_TTL_DAYS` (30 by default). The creator
also gets a private delete link, shown once; only its SHA-256 is stored. Shared pages send
`X-Robots-Tag: noindex` and `Cache-Control: no-store`. Scans that aren't shared are never written anywhere.
For code scans, secrets stay masked but file names are visible.

### Scheduled re-scans (monitoring)

Owners can have a site re-scanned **daily or weekly** and get an email only when it gets worse:

* a new medium, high or critical finding;
* a finding whose severity rose (e.g. a certificate moving from "expires in 30 days" to "expires in 14 days");
* a lower grade;
* the site couldn't be reached 3 times in a row.

The first run sends a "monitoring started" summary. Owners can also opt into a **weekly digest** (a checkbox at
setup, or a toggle on the manage page). It's one email a week with the grade against a week ago, how many scans
ran, what was found and fixed, and the top things to fix next. It's sent even when nothing got worse, and says
so when no scan succeeded that week. Digests read the monitor's saved reports, so keep
`RISKSCOPE_SHARE_TTL_DAYS` at 8 or more. Each run is saved as a report, so the monitor's manage page
shows the grade history with links to every scan.

Abuse protections: setting up a monitor requires the same **ownership verification** as active checks (it's
re-checked on every run, and active checks are only included while it still passes). It also requires
**email confirmation**: the link opens a page with an "Activate" button, because mail scanners that prefetch
links must not be able to switch it on. Unconfirmed requests are deleted after 7 days. There's a per-address
limit (`RISKSCOPE_MAX_MONITORS_PER_EMAIL`), and every email carries an RFC 8058 one-click `List-Unsubscribe`.
Each monitor's manage link holds an HMAC of its id under `RISKSCOPE_VERIFY_SECRET`, so a database leak alone
doesn't give unsubscribe rights.

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
curl 'http://127.0.0.1:8000/api/scan?target=example.com&share=true'    # response includes share_url / delete_url
curl 'http://127.0.0.1:8000/api/reports/<id>'                           # fetch a shared report as JSON
curl 'http://127.0.0.1:8000/api/ip-scan?target=1.1.1.1'                  # find & scan the site(s) on an IP
curl 'http://127.0.0.1:8000/api/ip-scan?target=1.1.1.0/30'              # ...or a small CIDR block
```

Without `RISKSCOPE_SMTP_HOST`, emails (monitor confirmations, alerts) are printed to the server log instead of
sent, so you can follow the links locally.

### Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `RISKSCOPE_VERIFY_SECRET` | random per process | HMAC key for ownership and monitor-management tokens. **Set it in production**: if it changes, verification tokens and every monitor's manage/unsubscribe link break |
| `RISKSCOPE_SCANS_PER_HOUR` | 20 | Scans per client IP per hour |
| `RISKSCOPE_MAX_UPLOAD_MB` | 20 | Upload size limit |
| `RISKSCOPE_MAX_CIDR_HOSTS` | 256 | Largest CIDR block (addresses) one IP scan may enumerate |
| `RISKSCOPE_MAX_IP_SITES` | 10 | Most sites one IP/CIDR request will scan |
| `RISKSCOPE_REVERSE_IP_PROVIDER` | none | Reverse-IP passive-DNS provider: `none` or `hackertarget` (sends the scanned IP to that service) |
| `RISKSCOPE_TRUST_PROXY` | false | Take the client IP from `X-Forwarded-For` (only behind your own proxy) |
| `RISKSCOPE_PUBLIC_BASE_URL` | `http://127.0.0.1:8000` | Absolute URL used in share links and emails |
| `RISKSCOPE_DATABASE_PATH` | `riskscope.db` (`/data/riskscope.db` in Docker) | SQLite file for shared reports and monitors |
| `RISKSCOPE_SHARE_TTL_DAYS` | 30 | Lifetime of shared reports and of monitor scan history |
| `RISKSCOPE_SCHEDULER_ENABLED` | true | Run the re-scan loop inside the web process |
| `RISKSCOPE_SCHEDULER_INTERVAL_S` | 300 | How often to look for due monitors |
| `RISKSCOPE_MAX_MONITORS_PER_EMAIL` | 5 | Sites one email address can monitor |
| `RISKSCOPE_SMTP_HOST` / `_PORT` / `_USERNAME` / `_PASSWORD` / `_FROM` / `_STARTTLS` | unset / 587 / … | Outgoing mail. Unset host = log emails instead |

## Deploying

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/alifjegham-wq/Riskscope)

The quickest way to put riskscope online is the Render blueprint (`render.yaml`). **[docs/DEPLOY.md](docs/DEPLOY.md)**
walks through it step by step, from a phone browser if you like, including email setup for monitoring. On a
public server without SMTP settings the monitoring sign-up stays hidden. The public URL defaults to the
platform's own (`RENDER_EXTERNAL_URL`), and the container listens on `$PORT`.

Any other Docker host works too:

```bash
docker build -t riskscope .
docker run -p 8000:8000 -v riskscope-data:/data \
  -e RISKSCOPE_VERIFY_SECRET=$(openssl rand -hex 32) \
  -e RISKSCOPE_PUBLIC_BASE_URL=https://scan.example.org \
  -e RISKSCOPE_SMTP_HOST=smtp.example.org -e RISKSCOPE_SMTP_USERNAME=... -e RISKSCOPE_SMTP_PASSWORD=... \
  -e RISKSCOPE_SMTP_FROM='riskscope <alerts@example.org>' \
  riskscope
```

Shared reports and monitors live in SQLite under `/data`, so mount a volume to keep them across restarts.
Run **one** web process: the scheduler runs inside it, and SQLite plus the in-memory rate limiter assume a
single process. To scale out, move the store to Postgres, set `RISKSCOPE_SCHEDULER_ENABLED=false` on all but one
instance (or run the scheduler as its own worker), and share the rate limiter.

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

`store.py` holds SQLite persistence and `monitoring.py` holds change detection, alert emails and the scheduler
loop (`Scheduler.tick()` runs due monitors once, which is how the tests drive it).

Each website check is a class with `name`, `title`, `active` and `async run(ctx) -> list[Finding]`
(`src/riskscope/checks/`). Register new checks in `checks/__init__.py`. Every finding needs a plain-language
`description`, a concrete `fix`, and snippets where config solves it. All network access goes through
`ScanContext` (`fetcher`, `dns`), which tests replace with fakes, so the test suite never touches the internet.

## Roadmap

- [x] Shareable report links (opt-in, expiring, deletable)
- [x] Scheduled re-scans with email alerts on regressions, certificate expiry and outages
- [ ] Background job queue so long scans don't hold a request open; Postgres store for multi-instance deploys
- [x] Weekly digest option for monitors
- [ ] Webhook/Slack alerts for monitors
- [x] Subdomain discovery from certificate transparency, plus dangling-CNAME (subdomain takeover) detection
- [ ] NS-delegation takeovers (subdomains delegated to unclaimed DNS zones) and scheduled fingerprint refresh
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
