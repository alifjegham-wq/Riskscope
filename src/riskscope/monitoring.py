"""Scheduled re-scans: run due monitors, compare with the last run, email on meaningful changes.

We alert only when something got worse (a new medium+ finding, a finding whose
severity rose, or a lower grade), so people keep reading the emails. The first
run of a new monitor always sends a "monitoring started" summary.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .models import Finding, Report, Severity
from .notify import Email, Mailer
from .safety import Target, parse_target
from .store import Monitor, Store

log = logging.getLogger(__name__)

#: Scan a target; the bool asks for active checks (they still require verified ownership).
ScanFn = Callable[[Target, bool], Awaitable[Report]]

ALERT_SEVERITIES = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
FAILURES_BEFORE_ALERT = 3
UNCONFIRMED_TTL_S = 7 * 86_400
_GRADE_ORDER = "ABCDF"


@dataclass
class Changes:
    new: list[Finding] = field(default_factory=list)
    worse: list[tuple[Finding, Severity]] = field(default_factory=list)  # (current, previous severity)
    resolved: list[Finding] = field(default_factory=list)
    old_grade: str | None = None
    new_grade: str = "A"

    @property
    def grade_dropped(self) -> bool:
        return self.old_grade is not None and _GRADE_ORDER.index(self.new_grade) > _GRADE_ORDER.index(self.old_grade)

    @property
    def alert(self) -> bool:
        return bool(self.new or self.worse or self.grade_dropped)


def diff_reports(previous: Report | None, current: Report) -> Changes:
    changes = Changes(old_grade=previous.grade if previous else None, new_grade=current.grade)
    if previous is None:
        return changes
    before = {f.id: f for f in previous.findings}
    after = {f.id: f for f in current.findings}
    for fid, f in after.items():
        old = before.get(fid)
        if old is None:
            if f.severity in ALERT_SEVERITIES:
                changes.new.append(f)
        elif f.severity.rank < old.severity.rank and f.severity in ALERT_SEVERITIES:
            changes.worse.append((f, old.severity))
    changes.resolved = [f for fid, f in before.items() if fid not in after]
    changes.new.sort(key=lambda f: f.severity.rank)
    return changes


def _lines(findings: list[Finding]) -> str:
    return "\n".join(f"  - [{f.severity.value.upper()}] {f.title}" for f in findings)


def alert_email(monitor: Monitor, report: Report, changes: Changes, report_url: str, manage_url: str) -> Email:
    parts = [f"riskscope re-scanned {monitor.target}: grade {report.grade} ({report.risk_level} risk)."]
    if changes.grade_dropped:
        parts.append(f"The grade dropped from {changes.old_grade} to {changes.new_grade}.")
    if changes.new:
        parts.append("New problems:\n" + _lines(changes.new))
    if changes.worse:
        parts.append(
            "Got worse:\n"
            + "\n".join(
                f"  - [{prev.value.upper()} -> {f.severity.value.upper()}] {f.title}" for f, prev in changes.worse
            )
        )
    if changes.resolved:
        parts.append("Fixed since last time:\n" + _lines(changes.resolved))
    parts.append(f"Full report and how to fix: {report_url}")
    parts.append(f"Change frequency or stop these emails: {manage_url}")
    subject = (
        f"[riskscope] {monitor.target} dropped to {report.grade}"
        if changes.grade_dropped
        else f"[riskscope] New security issues on {monitor.target}"
    )
    return Email(monitor.email, subject, "\n\n".join(parts) + "\n", unsubscribe_url=manage_url + "/unsubscribe")


def started_email(monitor: Monitor, report: Report, report_url: str, manage_url: str) -> Email:
    counts = report.counts()
    summary = ", ".join(f"{n} {s.value}" for s, n in counts.items() if n) or "no issues"
    body = (
        f"Monitoring is active for {monitor.target} ({monitor.frequency.value}).\n\n"
        f"First scan: grade {report.grade} ({report.risk_level} risk), {summary}.\n\n"
        f"Full report: {report_url}\n\n"
        "We'll only email you again when something gets worse: a new issue, a higher severity, or a lower grade.\n\n"
        f"Manage or stop monitoring: {manage_url}\n"
    )
    return Email(
        monitor.email,
        f"[riskscope] Monitoring {monitor.target}: grade {report.grade}",
        body,
        unsubscribe_url=manage_url + "/unsubscribe",
    )


def failure_email(monitor: Monitor, error: str, manage_url: str) -> Email:
    body = (
        f"riskscope could not scan {monitor.target} {FAILURES_BEFORE_ALERT} times in a row.\n\n"
        f"Last error: {error}\n\n"
        "If the site is down, that may be worth checking. If you moved or retired it, you can stop monitoring here:\n"
        f"{manage_url}\n"
    )
    return Email(
        monitor.email, f"[riskscope] Can't reach {monitor.target}", body, unsubscribe_url=manage_url + "/unsubscribe"
    )


def confirm_email(monitor: Monitor, manage_url: str) -> Email:
    body = (
        f"Someone (hopefully you) asked riskscope to re-scan {monitor.target} {monitor.frequency.value} "
        f"and email {monitor.email} when its security gets worse.\n\n"
        f'To switch it on, open this link and press "Activate":\n{manage_url}\n\n'
        "If this wasn't you, ignore this email and nothing will happen. The request is deleted after 7 days.\n"
    )
    return Email(monitor.email, f"[riskscope] Confirm monitoring for {monitor.target}", body)


@dataclass
class Scheduler:
    store: Store
    scan: ScanFn
    mailer: Mailer
    base_url: str
    report_ttl_s: float
    #: Builds the monitor's private manage URL (it embeds the HMAC token).
    manage_link: Callable[[Monitor], str]

    async def _send(self, email: Email) -> None:
        try:
            await self.mailer.send(email)
        except Exception:  # noqa: BLE001 - a mail outage must not stop the remaining monitors in this tick
            log.exception("could not send %r to %s", email.subject, email.to)

    async def run_monitor(self, monitor: Monitor) -> None:
        try:
            report = await self.scan(parse_target(monitor.target), True)
        except Exception as exc:  # noqa: BLE001 - record and move on; one bad site must not stop the loop
            log.info("monitor %s scan failed: %s", monitor.id, exc)
            await asyncio.to_thread(self.store.record_run, monitor.id, None)
            if monitor.failures + 1 == FAILURES_BEFORE_ALERT:
                await self._send(failure_email(monitor, str(exc) or type(exc).__name__, self.manage_link(monitor)))
            return

        previous = None
        if monitor.last_report_id:
            stored = await asyncio.to_thread(self.store.get_report, monitor.last_report_id, allow_expired=True)
            previous = stored.report if stored else None
        rid, _ = await asyncio.to_thread(self.store.save_report, report, self.report_ttl_s, monitor_id=monitor.id)
        await asyncio.to_thread(self.store.record_run, monitor.id, rid)

        report_url = f"{self.base_url}/r/{rid}"
        manage_url = self.manage_link(monitor)
        if monitor.last_report_id is None:
            await self._send(started_email(monitor, report, report_url, manage_url))
            return
        changes = diff_reports(previous, report)
        if changes.alert:
            await self._send(alert_email(monitor, report, changes, report_url, manage_url))

    async def tick(self, now: float | None = None) -> int:
        """Run every due monitor once; returns how many ran."""
        await asyncio.to_thread(self.store.purge_expired)
        await asyncio.to_thread(self.store.delete_unconfirmed, UNCONFIRMED_TTL_S)
        due = await asyncio.to_thread(self.store.claim_due, now)
        for monitor in due:
            # Sequential on purpose: gentle on targets and on our own outbound bandwidth.
            await self.run_monitor(monitor)
        return len(due)

    async def run_forever(self, interval_s: float) -> None:
        while True:
            started = time.monotonic()
            try:
                await self.tick()
            except Exception:  # noqa: BLE001 - keep the scheduler alive; errors are logged
                log.exception("scheduler tick failed")
            await asyncio.sleep(max(1.0, interval_s - (time.monotonic() - started)))
