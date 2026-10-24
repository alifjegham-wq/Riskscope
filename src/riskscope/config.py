from __future__ import annotations

import secrets

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RISKSCOPE_", env_file=".env", extra="ignore")

    #: HMAC key for ownership tokens. Set it in production, or tokens change on every restart.
    verify_secret: str = secrets.token_hex(32)
    #: Website + code scans allowed per client IP per hour.
    scans_per_hour: int = 20
    max_upload_mb: int = 20
    #: Read the client IP from X-Forwarded-For (only behind a proxy you control).
    trust_proxy: bool = False
    http_timeout_s: float = 10.0
