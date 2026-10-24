from __future__ import annotations

import os
import secrets
from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_base_url() -> str:
    # Render sets RENDER_EXTERNAL_URL to the service's public https:// address.
    if url := os.environ.get("RENDER_EXTERNAL_URL"):
        return url
    # GitHub Codespaces forwards ports to https://<codespace>-<port>.<domain>.
    name, domain = os.environ.get("CODESPACE_NAME"), os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN")
    if name and domain:
        return f"https://{name}-{os.environ.get('PORT', '8000')}.{domain}"
    return "http://127.0.0.1:8000"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RISKSCOPE_", env_file=".env", extra="ignore")

    #: HMAC key for ownership and monitor-management tokens. Set it in production: if it changes,
    #: verification tokens and every monitor's manage/unsubscribe link stop working.
    verify_secret: str = secrets.token_hex(32)
    #: Website + code scans allowed per client IP per hour.
    scans_per_hour: int = 20
    max_upload_mb: int = 20
    #: Read the client IP from X-Forwarded-For (only behind a proxy you control).
    trust_proxy: bool = False
    http_timeout_s: float = 10.0

    # ---- scanning by IP / CIDR ---------------------------------------------
    #: Largest CIDR block (number of addresses) one request may enumerate.
    max_cidr_hosts: int = 256
    #: Most distinct sites one IP/CIDR request will actually scan.
    max_ip_sites: int = 10
    #: Passive-DNS provider for reverse-IP lookups: "none" (default) or "hackertarget".
    #: Anything but "none" sends the scanned IP to that third-party service.
    reverse_ip_provider: str = "none"

    # ---- shared reports & monitoring ---------------------------------------
    #: SQLite file for opt-in shared reports and monitors (":memory:" for tests).
    database_path: str = "riskscope.db"
    #: False on hosts whose disk is wiped on restart (free tiers): shareable links and monitoring are then
    #: hidden, because saved reports and monitors would silently disappear.
    persistent_storage: bool = True
    #: Absolute base URL used in share links and emails, e.g. https://riskscope.example.org.
    #: Defaults to the hosting platform's public URL when it provides one (Render), else localhost.
    public_base_url: str = Field(default_factory=_default_base_url)
    share_ttl_days: int = 30
    scheduler_enabled: bool = True
    scheduler_interval_s: float = 300.0
    max_monitors_per_email: int = 5

    #: Leave smtp_host empty in development: emails are then logged instead of sent.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "riskscope <no-reply@localhost>"
    smtp_starttls: bool = True

    @field_validator("public_base_url", mode="before")
    @classmethod
    def _blank_base_url(cls, v: object) -> object:
        # Hosting dashboards often pass optional variables as empty strings.
        return v.strip() or _default_base_url() if isinstance(v, str) else v

    @field_validator("smtp_from", mode="before")
    @classmethod
    def _blank_sender(cls, v: object) -> object:
        return v.strip() or "riskscope <no-reply@localhost>" if isinstance(v, str) else v

    @property
    def is_local(self) -> bool:
        """Running on this machine (development), judged by the public base URL."""
        return urlsplit(self.public_base_url).hostname in ("127.0.0.1", "localhost", "::1")
