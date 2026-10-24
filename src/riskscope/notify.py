"""Outbound email. SMTP in production; logged to stdout when no SMTP host is configured (development)."""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Email:
    to: str
    subject: str
    body: str
    #: URL for RFC 8058 one-click unsubscribe (POST), when the mail is about a monitor.
    unsubscribe_url: str | None = None


class Mailer(Protocol):
    async def send(self, email: Email) -> None: ...


class LogMailer:
    """Development mailer: prints instead of sending so links can be followed locally."""

    def __init__(self) -> None:
        self.sent: list[Email] = []

    async def send(self, email: Email) -> None:
        self.sent.append(email)
        log.warning("email (not sent, no SMTP configured) to=%s subject=%s\n%s", email.to, email.subject, email.body)


class SmtpMailer:
    def __init__(
        self, host: str, port: int, sender: str, username: str = "", password: str = "", starttls: bool = True
    ) -> None:
        self.host, self.port, self.sender = host, port, sender
        self.username, self.password, self.starttls = username, password, starttls

    def _send_sync(self, email: Email) -> None:
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = email.to
        msg["Subject"] = email.subject
        if email.unsubscribe_url:
            msg["List-Unsubscribe"] = f"<{email.unsubscribe_url}>"
            msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
        msg.set_content(email.body)
        with smtplib.SMTP(self.host, self.port, timeout=30) as smtp:
            if self.starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self.username:
                smtp.login(self.username, self.password)
            smtp.send_message(msg)

    async def send(self, email: Email) -> None:
        await asyncio.to_thread(self._send_sync, email)
