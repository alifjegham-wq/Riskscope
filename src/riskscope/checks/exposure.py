"""Files and pages that should never be public.

Each path has a content signature, so "soft 404" sites that answer 200 to
everything do not produce false positives. Requests are single GETs of well
known paths: nothing a search-engine crawler would not also try.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass

from ..models import Category, Finding, Severity
from ..safety import UnsafeTargetError
from .base import ScanContext

CONCURRENCY = 4


def _text(pattern: str, flags: int = 0) -> Callable[[bytes], bool]:
    rx = re.compile(pattern.encode(), flags)

    def match(body: bytes) -> bool:
        head = body[:65536]
        return b"<html" not in head[:2048].lower() and bool(rx.search(head))

    return match


def _magic(prefix: bytes) -> Callable[[bytes], bool]:
    return lambda body: body.startswith(prefix)


@dataclass(frozen=True)
class Probe:
    path: str
    title: str
    severity: Severity
    why: str
    matches: Callable[[bytes], bool]
    # Some probes target app endpoints rather than stray files; they carry their own
    # remediation. When unset, a generic "delete the file / block dotfiles" fix is used.
    fix: str | None = None
    snippets: dict[str, str] | None = None
    references: tuple[str, ...] = ()


PROBES: tuple[Probe, ...] = (
    Probe(
        "/.git/HEAD",
        "Git repository is downloadable",
        Severity.CRITICAL,
        "Attackers can rebuild your full source code, including history and any secrets ever committed.",
        _text(r"^ref: refs/"),
    ),
    Probe(
        "/.git/config",
        "Git configuration is downloadable",
        Severity.CRITICAL,
        "The .git folder is public; source code and credentials in remotes may be exposed.",
        _text(r"\[core\]"),
    ),
    Probe(
        "/.env",
        "Environment file (.env) is public",
        Severity.CRITICAL,
        ".env files usually hold database passwords and API keys.",
        _text(r"(?m)^[A-Z][A-Z0-9_]{2,}=.+\n[A-Z][A-Z0-9_]{2,}="),
    ),
    Probe(
        "/.aws/credentials",
        "AWS credentials file is public",
        Severity.CRITICAL,
        "These keys give direct access to your cloud account.",
        _text(r"aws_access_key_id", re.I),
    ),
    Probe(
        "/wp-config.php.bak",
        "WordPress config backup is public",
        Severity.CRITICAL,
        "Backup copies are served as plain text, revealing database credentials and salts.",
        _text(r"DB_PASSWORD"),
    ),
    Probe(
        "/backup.sql",
        "Database dump is public",
        Severity.CRITICAL,
        "A full copy of your database, often including customer data and password hashes.",
        _text(r"CREATE TABLE|INSERT INTO", re.I),
    ),
    Probe(
        "/dump.sql",
        "Database dump is public",
        Severity.CRITICAL,
        "A full copy of your database, often including customer data and password hashes.",
        _text(r"CREATE TABLE|INSERT INTO", re.I),
    ),
    Probe(
        "/.htpasswd",
        "Password file (.htpasswd) is public",
        Severity.HIGH,
        "Password hashes can be cracked offline.",
        _text(r"(?m)^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\})"),
    ),
    Probe(
        "/backup.zip",
        "Site backup archive is public",
        Severity.HIGH,
        "Backups usually contain source code, configs and data.",
        _magic(b"PK\x03\x04"),
    ),
    Probe(
        "/server-status",
        "Apache server-status page is public",
        Severity.MEDIUM,
        "Shows live requests, client IPs and internal URLs.",
        lambda b: b"Apache Server Status" in b[:65536],
    ),
    Probe(
        "/phpinfo.php",
        "phpinfo() page is public",
        Severity.MEDIUM,
        "Reveals exact versions, paths and configuration useful for targeting exploits.",
        lambda b: b"<title>PHP " in b[:65536] and b"phpinfo" in b[:65536],
    ),
    Probe(
        "/info.php",
        "phpinfo() page is public",
        Severity.MEDIUM,
        "Reveals exact versions, paths and configuration useful for targeting exploits.",
        lambda b: b"<title>PHP " in b[:65536] and b"phpinfo" in b[:65536],
    ),
    Probe(
        "/.DS_Store",
        "macOS .DS_Store file is public",
        Severity.LOW,
        "Lists file names in the folder, which can reveal hidden files.",
        _magic(b"\x00\x00\x00\x01Bud1"),
    ),
    Probe(
        "/.svn/wc.db",
        "Subversion repository is downloadable",
        Severity.CRITICAL,
        "The .svn working copy is public; attackers can recover your full source code.",
        _magic(b"SQLite format 3\x00"),
    ),
    Probe(
        "/.hg/requires",
        "Mercurial repository is downloadable",
        Severity.HIGH,
        "The .hg folder is public; source history may be recoverable.",
        _text(r"revlogv1|dotencode|store|fncache"),
    ),
    Probe(
        "/.git-credentials",
        "Git credentials file is public",
        Severity.CRITICAL,
        "This file stores git usernames and passwords/tokens in plain text.",
        _text(r"https?://[^:/\s]+:[^@/\s]+@"),
    ),
    Probe(
        "/.env.local",
        "Environment file (.env.local) is public",
        Severity.CRITICAL,
        ".env files usually hold database passwords and API keys.",
        _text(r"(?m)^[A-Z][A-Z0-9_]{2,}=.+\n[A-Z][A-Z0-9_]{2,}="),
    ),
    Probe(
        "/.env.production",
        "Environment file (.env.production) is public",
        Severity.CRITICAL,
        ".env files usually hold database passwords and API keys.",
        _text(r"(?m)^[A-Z][A-Z0-9_]{2,}=.+\n[A-Z][A-Z0-9_]{2,}="),
    ),
    Probe(
        "/wp-config.php~",
        "WordPress config backup is public",
        Severity.CRITICAL,
        "Editor backup copies are served as plain text, revealing database credentials and salts.",
        _text(r"DB_PASSWORD"),
    ),
    Probe(
        "/storage/logs/laravel.log",
        "Laravel log file is public",
        Severity.HIGH,
        "Application logs leak stack traces, file paths and sometimes credentials or tokens.",
        _text(r"\] (?:local|production|staging)\.(?:ERROR|WARNING|CRITICAL)"),
    ),
    Probe(
        "/.vscode/sftp.json",
        "VS Code SFTP config (with credentials) is public",
        Severity.HIGH,
        "This editor config often contains the deploy server host, username and password or key path.",
        _text(r'"(?:password|privateKeyPath|host|username)"'),
    ),
    Probe(
        "/docker-compose.yml",
        "docker-compose.yml is public",
        Severity.MEDIUM,
        "Compose files reveal your services and often embed passwords and secrets in environment blocks.",
        _text(r"(?m)^\s*(?:services|image|environment):"),
    ),
    Probe(
        "/composer.lock",
        "composer.lock is public",
        Severity.LOW,
        "Reveals the exact PHP package versions you run, making it easy to target known vulnerabilities.",
        _text(r'"(?:packages|content-hash)"'),
    ),
    Probe(
        "/adminer.php",
        "Adminer database tool is exposed",
        Severity.MEDIUM,
        "A public database login tool is a direct target for credential attacks.",
        lambda b: b"Adminer" in b[:65536] and b"login" in b[:65536].lower(),
    ),
    Probe(
        "/phpmyadmin/",
        "phpMyAdmin is exposed",
        Severity.MEDIUM,
        "A public database admin login is a constant target for brute-force and known-exploit attacks.",
        lambda b: b"phpMyAdmin" in b[:65536],
    ),
    # --- Cloud / CI / infra secrets (OWASP 2025 A02 Security Misconfiguration, A03 Supply Chain) ---
    Probe(
        "/.env.bak",
        "Environment backup file is public",
        Severity.CRITICAL,
        ".env backups are served as plain text, revealing database passwords and API keys.",
        _text(r"(?m)^[A-Z][A-Z0-9_]{2,}=.+\n[A-Z][A-Z0-9_]{2,}="),
    ),
    Probe(
        "/.env.old",
        "Environment backup file is public",
        Severity.CRITICAL,
        ".env backups are served as plain text, revealing database passwords and API keys.",
        _text(r"(?m)^[A-Z][A-Z0-9_]{2,}=.+\n[A-Z][A-Z0-9_]{2,}="),
    ),
    Probe(
        "/.npmrc",
        "npm config with auth token is public",
        Severity.HIGH,
        "An _authToken in .npmrc lets an attacker publish packages to your registry account.",
        _text(r"_authToken\s*=|:_password="),
        fix="Remove /.npmrc from the web root and revoke the exposed npm token now.",
        references=("https://docs.npmjs.com/revoking-access-tokens",),
    ),
    Probe(
        "/.kube/config",
        "Kubernetes kubeconfig is public",
        Severity.CRITICAL,
        "A kubeconfig hands over cluster credentials — often full admin of your Kubernetes cluster.",
        _text(r"(?m)^(?:apiVersion|clusters|current-context):"),
        fix="Remove /.kube/config from the web root and rotate the cluster credentials / client certs.",
    ),
    Probe(
        "/terraform.tfstate",
        "Terraform state file is public",
        Severity.HIGH,
        "Terraform state records your whole infrastructure and stores many secrets (DB passwords, keys) in clear text.",
        _text(r'"terraform_version"\s*:'),
        fix="Remove the state file from the web root and move state to a private remote backend. "
        "Rotate any secrets it contained.",
        references=("https://developer.hashicorp.com/terraform/language/state/sensitive-data",),
    ),
    Probe(
        "/appsettings.json",
        "ASP.NET appsettings.json is public",
        Severity.HIGH,
        "This config usually holds ConnectionStrings and API keys in clear text.",
        _text(r'"ConnectionStrings"\s*:'),
        fix="Block appsettings.json in the server config and move secrets to environment variables or a "
        "secrets store. Rotate any that leaked.",
    ),
    Probe(
        "/actuator/env",
        "Spring Boot Actuator /env is public",
        Severity.HIGH,
        "The env endpoint dumps configuration and environment variables, often exposing credentials.",
        _text(r'"(?:propertySources|activeProfiles)"\s*:'),
        fix="Restrict Spring Boot Actuator: expose only health, and secure the rest "
        "(management.endpoints.web.exposure.include). Rotate anything that leaked.",
        references=(
            "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html#actuator.endpoints.security",
        ),
    ),
    Probe(
        "/actuator/heapdump",
        "Spring Boot Actuator heap dump is public",
        Severity.CRITICAL,
        "A heap dump is a snapshot of application memory — it contains live credentials, tokens and session data.",
        _magic(b"JAVA PROFILE"),
        fix="Disable the heapdump endpoint and never expose Actuator publicly. Rotate any secrets the "
        "application held in memory.",
        references=(
            "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html#actuator.endpoints.security",
        ),
    ),
    Probe(
        "/@vite/client",
        "Vite dev server is exposed in production",
        Severity.HIGH,
        "A running Vite dev server exposes source files and, via the /@fs/ route (CVE-2026-39364), can "
        "serve arbitrary files from the host.",
        _text(r"createHotContext|__vite__|import\.meta\.hot"),
        fix="Never run the Vite dev server in production. Build with `vite build` and serve the static "
        "output; keep the dev server bound to localhost.",
        references=("https://nvd.nist.gov/vuln/detail/CVE-2026-39364",),
    ),
    # --- Keys, server config and source history ---
    Probe(
        "/.ssh/id_rsa",
        "Private SSH key is public",
        Severity.CRITICAL,
        "A private SSH key gives an attacker login access to whatever servers trust it.",
        _text(r"BEGIN (?:RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY"),
        fix="Remove the key from the web root and rotate it (generate a new keypair) immediately.",
    ),
    Probe(
        "/id_rsa",
        "Private SSH key is public",
        Severity.CRITICAL,
        "A private SSH key gives an attacker login access to whatever servers trust it.",
        _text(r"BEGIN (?:RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY"),
        fix="Remove the key from the web root and rotate it (generate a new keypair) immediately.",
    ),
    Probe(
        "/web.config",
        "IIS web.config is public",
        Severity.HIGH,
        "web.config often holds connection strings, machine keys and app settings in clear text.",
        _text(r"<configuration\b|<connectionStrings\b|<machineKey\b"),
        fix="Block web.config in the server config (IIS normally does; a misconfigured proxy may not). "
        "Rotate any secrets it exposed.",
    ),
    Probe(
        "/.git/logs/HEAD",
        "Git history log is public",
        Severity.MEDIUM,
        "The reflog reveals commit hashes and committer names/emails, and helps reconstruct the repo even "
        "when /.git/HEAD is blocked.",
        _text(r"(?m)^[0-9a-f]{40} [0-9a-f]{40} "),
    ),
    Probe(
        "/config.php.bak",
        "PHP config backup is public",
        Severity.HIGH,
        "Editor/backup copies of config.php are served as source, revealing database and app credentials.",
        _text(r"<\?php"),
    ),
    Probe(
        "/config.php~",
        "PHP config backup is public",
        Severity.HIGH,
        "Editor/backup copies of config.php are served as source, revealing database and app credentials.",
        _text(r"<\?php"),
    ),
    Probe(
        "/sftp-config.json",
        "Sublime SFTP config (with credentials) is public",
        Severity.HIGH,
        "This editor config usually contains the deploy host, username and password or key path.",
        _text(r'"(?:password|host|user|remote_path)"'),
    ),
    Probe(
        "/swagger.json",
        "API schema (Swagger/OpenAPI) is public",
        Severity.LOW,
        "A public API schema maps every endpoint and parameter, which makes targeted attacks much easier.",
        _text(r'"(?:swagger|openapi)"\s*:'),
        fix="Serve API docs only to authenticated users, or remove them from production.",
    ),
    Probe(
        "/openapi.json",
        "API schema (Swagger/OpenAPI) is public",
        Severity.LOW,
        "A public API schema maps every endpoint and parameter, which makes targeted attacks much easier.",
        _text(r'"(?:swagger|openapi)"\s*:'),
        fix="Serve API docs only to authenticated users, or remove them from production.",
    ),
)


class ExposedFilesCheck:
    name = "exposed_files"
    title = "Exposed sensitive files"
    active = False

    def __init__(self, probes: tuple[Probe, ...] = PROBES) -> None:
        self.probes = probes

    async def run(self, ctx: ScanContext) -> list[Finding]:
        sem = asyncio.Semaphore(CONCURRENCY)
        base = ctx.target.url.rstrip("/")

        async def one(p: Probe) -> Finding | None:
            async with sem:
                try:
                    res = await ctx.fetcher.get(base + p.path, follow_redirects=False)
                except (UnsafeTargetError, OSError):
                    return None
                except Exception:  # noqa: BLE001 - one odd response must not sink the whole check
                    return None
            if res.response.status_code != 200 or not p.matches(res.body):
                return None
            return Finding(
                id=f"exposure{p.path.replace('/', '.')}",
                title=p.title,
                severity=p.severity,
                category=Category.EXPOSURE,
                description=p.why,
                evidence=f"GET {p.path} -> 200 with matching content",
                fix=p.fix
                or (
                    f"Delete /{p.path.split('/')[1]} from the web root (or block it in the server config). "
                    "If it held secrets, treat them as leaked and rotate them now."
                ),
                snippets=p.snippets
                if p.snippets is not None
                else {
                    "nginx": "location ~ /\\.(?!well-known) { deny all; }",
                    "Apache": '<FilesMatch "^\\.">\n  Require all denied\n</FilesMatch>',
                },
                references=list(p.references),
            )

        results = await asyncio.gather(*(one(p) for p in self.probes))
        out = [f for f in results if f is not None]
        # Collapse duplicates (e.g. both dump paths) to one finding per title.
        seen: set[str] = set()
        unique = []
        for f in out:
            if f.title not in seen:
                seen.add(f.title)
                unique.append(f)

        home = await ctx.homepage()
        if re.search(rb"<title>\s*Index of /", home.body[:4096], re.I):
            unique.append(
                Finding(
                    id="exposure.directory_listing",
                    title="Directory listing is enabled",
                    severity=Severity.MEDIUM,
                    category=Category.EXPOSURE,
                    description="Anyone can browse every file in the folder, including ones you did not link to.",
                    fix="Turn off auto-indexing.",
                    snippets={"nginx": "autoindex off;", "Apache": "Options -Indexes"},
                )
            )
        return unique


class SecurityTxtCheck:
    name = "security_txt"
    title = "security.txt (vulnerability disclosure contact)"
    active = False

    async def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            res = await ctx.fetcher.get(ctx.target.url + ".well-known/security.txt")
            ok = res.response.status_code == 200 and b"contact:" in res.body[:16384].lower()
        except (UnsafeTargetError, OSError):
            ok = False
        if ok:
            return []
        return [
            Finding(
                id="disclosure.security_txt.missing",
                title="No security.txt",
                severity=Severity.INFO,
                category=Category.EXPOSURE,
                description="Researchers who find a problem have no published way to tell you about it.",
                fix="Publish /.well-known/security.txt with a Contact and Expires line (RFC 9116).",
                snippets={
                    "security.txt": "Contact: mailto:security@example.com\nExpires: 2027-12-31T23:59:59Z\n"
                    "Preferred-Languages: en"
                },
                references=["https://securitytxt.org/"],
            )
        ]
