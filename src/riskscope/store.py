"""SQLite persistence for opt-in shared reports and scheduled monitors.

Nothing is stored unless the user asks: a plain scan never touches the store.
Public ids are unguessable (128-bit). A shared report's delete token is
random and only its SHA-256 is kept; a monitor's manage token is an HMAC of
its id (see `monitor_token`) so scheduled emails can re-create the link.
Either way a database leak alone does not hand out delete/unsubscribe rights.

Methods are synchronous (sqlite3); the web layer calls them via
``asyncio.to_thread``. One connection guarded by a lock is plenty for a single
process; swap this class for Postgres before running several workers.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import StrEnum

from .models import Report

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id          TEXT PRIMARY KEY,
    manage_hash TEXT NOT NULL,
    monitor_id  TEXT REFERENCES monitors(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    target      TEXT NOT NULL,
    grade       TEXT NOT NULL,
    score       INTEGER NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    body        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reports_expiry ON reports(expires_at);
CREATE INDEX IF NOT EXISTS reports_monitor ON reports(monitor_id, created_at);

CREATE TABLE IF NOT EXISTS monitors (
    id             TEXT PRIMARY KEY,
    target         TEXT NOT NULL,
    email          TEXT NOT NULL,
    frequency      TEXT NOT NULL,
    confirmed      INTEGER NOT NULL DEFAULT 0,
    created_at     REAL NOT NULL,
    next_run_at    REAL NOT NULL,
    last_report_id TEXT,
    failures       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS monitors_due ON monitors(confirmed, next_run_at);
CREATE INDEX IF NOT EXISTS monitors_email ON monitors(email);
"""


class Frequency(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"

    @property
    def seconds(self) -> int:
        return 86_400 if self is Frequency.DAILY else 7 * 86_400


def new_id() -> str:
    return secrets.token_urlsafe(16)


def new_token() -> str:
    return secrets.token_urlsafe(24)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def monitor_token(secret: str, monitor_id: str) -> str:
    return hmac.new(secret.encode(), b"monitor:" + monitor_id.encode(), hashlib.sha256).hexdigest()[:40]


def check_monitor_token(secret: str, monitor_id: str, token: str) -> bool:
    return hmac.compare_digest(monitor_token(secret, monitor_id).encode(), token.encode())


@dataclass(frozen=True)
class StoredReport:
    id: str
    report: Report
    created_at: float
    expires_at: float
    monitor_id: str | None


@dataclass(frozen=True)
class Monitor:
    id: str
    target: str
    email: str
    frequency: Frequency
    confirmed: bool
    created_at: float
    next_run_at: float
    last_report_id: str | None
    failures: int


@dataclass(frozen=True)
class HistoryPoint:
    report_id: str
    created_at: float
    grade: str
    score: int


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("PRAGMA foreign_keys = ON")
            if path != ":memory:":
                self._db.execute("PRAGMA journal_mode = WAL")
            self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---- reports -----------------------------------------------------------

    def save_report(
        self, report: Report, ttl_s: float, *, monitor_id: str | None = None, now: float | None = None
    ) -> tuple[str, str]:
        """Persist a report; returns (public id, manage token)."""
        now = time.time() if now is None else now
        rid, token = new_id(), new_token()
        with self._lock:
            self._db.execute(
                "INSERT INTO reports (id, manage_hash, monitor_id, kind, target, grade, score, created_at, expires_at,"
                " body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    rid,
                    token_hash(token),
                    monitor_id,
                    report.kind,
                    report.target,
                    report.grade,
                    report.score,
                    now,
                    now + ttl_s,
                    report.model_dump_json(),
                ),
            )
        return rid, token

    def get_report(self, rid: str, now: float | None = None, *, allow_expired: bool = False) -> StoredReport | None:
        now = float("-inf") if allow_expired else (time.time() if now is None else now)
        with self._lock:
            row = self._db.execute(
                "SELECT id, body, created_at, expires_at, monitor_id FROM reports WHERE id = ? AND expires_at > ?",
                (rid, now),
            ).fetchone()
        if row is None:
            return None
        return StoredReport(
            id=row["id"],
            report=Report.model_validate_json(row["body"]),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            monitor_id=row["monitor_id"],
        )

    def check_report_token(self, rid: str, token: str) -> bool:
        with self._lock:
            row = self._db.execute("SELECT manage_hash FROM reports WHERE id = ?", (rid,)).fetchone()
        return row is not None and secrets.compare_digest(row["manage_hash"], token_hash(token))

    def delete_report(self, rid: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM reports WHERE id = ?", (rid,))

    def purge_expired(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            # Keep a monitor's latest report even past expiry: the next run diffs against it.
            cur = self._db.execute(
                "DELETE FROM reports WHERE expires_at <= ? AND id NOT IN "
                "(SELECT last_report_id FROM monitors WHERE last_report_id IS NOT NULL)",
                (now,),
            )
        return cur.rowcount

    # ---- monitors ----------------------------------------------------------

    def create_monitor(self, target: str, email: str, frequency: Frequency, now: float | None = None) -> Monitor:
        now = time.time() if now is None else now
        mid = new_id()
        with self._lock:
            self._db.execute(
                "INSERT INTO monitors (id, target, email, frequency, created_at, next_run_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (mid, target, email.lower(), frequency.value, now, now),
            )
        monitor = self.get_monitor(mid)
        assert monitor is not None
        return monitor

    def get_monitor(self, mid: str) -> Monitor | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM monitors WHERE id = ?", (mid,)).fetchone()
        return _monitor(row) if row else None

    def count_monitors_for_email(self, email: str) -> int:
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) FROM monitors WHERE email = ?", (email.lower(),)).fetchone()
        return int(row[0])

    def find_monitor(self, target: str, email: str) -> Monitor | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM monitors WHERE target = ? AND email = ?", (target, email.lower())
            ).fetchone()
        return _monitor(row) if row else None

    def set_frequency(self, mid: str, frequency: Frequency) -> None:
        with self._lock:
            self._db.execute("UPDATE monitors SET frequency = ? WHERE id = ?", (frequency.value, mid))

    def confirm_monitor(self, mid: str, now: float | None = None) -> None:
        """Activate; the first scan runs on the next scheduler tick."""
        now = time.time() if now is None else now
        with self._lock:
            self._db.execute("UPDATE monitors SET confirmed = 1, next_run_at = ? WHERE id = ?", (now, mid))

    def delete_monitor(self, mid: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM monitors WHERE id = ?", (mid,))

    def delete_unconfirmed(self, older_than_s: float, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM monitors WHERE confirmed = 0 AND created_at <= ?", (now - older_than_s,)
            )
        return cur.rowcount

    def claim_due(self, now: float | None = None, limit: int = 10) -> list[Monitor]:
        """Return due monitors and push their next run forward so no other tick picks them up."""
        now = time.time() if now is None else now
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                rows = self._db.execute(
                    "SELECT * FROM monitors WHERE confirmed = 1 AND next_run_at <= ? ORDER BY next_run_at LIMIT ?",
                    (now, limit),
                ).fetchall()
                for row in rows:
                    period = Frequency(row["frequency"]).seconds
                    self._db.execute("UPDATE monitors SET next_run_at = ? WHERE id = ?", (now + period, row["id"]))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return [_monitor(r) for r in rows]

    def record_run(self, mid: str, report_id: str | None) -> None:
        """A successful run resets failures; a failed one (report_id None) increments them."""
        with self._lock:
            if report_id is None:
                self._db.execute("UPDATE monitors SET failures = failures + 1 WHERE id = ?", (mid,))
            else:
                self._db.execute("UPDATE monitors SET failures = 0, last_report_id = ? WHERE id = ?", (report_id, mid))

    def history(self, mid: str, limit: int = 30) -> list[HistoryPoint]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, created_at, grade, score FROM reports WHERE monitor_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (mid, limit),
            ).fetchall()
        return [HistoryPoint(r["id"], r["created_at"], r["grade"], r["score"]) for r in rows]


def _monitor(row: sqlite3.Row) -> Monitor:
    return Monitor(
        id=row["id"],
        target=row["target"],
        email=row["email"],
        frequency=Frequency(row["frequency"]),
        confirmed=bool(row["confirmed"]),
        created_at=row["created_at"],
        next_run_at=row["next_run_at"],
        last_report_id=row["last_report_id"],
        failures=row["failures"],
    )
