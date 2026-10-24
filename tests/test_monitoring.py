import pytest

from riskscope.models import Category, Finding, Report, Severity
from riskscope.monitoring import FAILURES_BEFORE_ALERT, Scheduler, diff_reports
from riskscope.notify import Email, LogMailer
from riskscope.safety import Target
from riskscope.scoring import apply_score
from riskscope.store import Frequency, Monitor, Store


def finding(fid: str, sev: Severity) -> Finding:
    return Finding(id=fid, title=fid, severity=sev, category=Category.HEADERS, description="")


def report(*findings: Finding) -> Report:
    return apply_score(Report(target="example.com", kind="website", findings=list(findings)))


def test_diff_detects_new_worse_resolved_and_grade_drop() -> None:
    before = report(finding("a", Severity.MEDIUM), finding("gone", Severity.LOW), finding("tls", Severity.MEDIUM))
    after = report(
        finding("a", Severity.MEDIUM),
        finding("tls", Severity.HIGH),
        finding("new", Severity.HIGH),
        finding("x", Severity.LOW),
    )
    c = diff_reports(before, after)
    assert [f.id for f in c.new] == ["new"]  # low-severity "x" doesn't alert
    assert [(f.id, prev) for f, prev in c.worse] == [("tls", Severity.MEDIUM)]
    assert [f.id for f in c.resolved] == ["gone"]
    assert c.alert


def test_diff_quiet_when_nothing_worse() -> None:
    before = report(finding("a", Severity.HIGH))
    after = report(finding("a", Severity.HIGH), finding("b", Severity.INFO))
    assert not diff_reports(before, after).alert
    assert not diff_reports(before, report()).alert  # fixes alone don't email


class FakeScan:
    def __init__(self, reports: list[Report | Exception]) -> None:
        self.reports = reports
        self.calls: list[tuple[str, bool]] = []

    async def __call__(self, target: Target, want_active: bool) -> Report:
        self.calls.append((target.host, want_active))
        r = self.reports.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def make(reports: list[Report | Exception]) -> tuple[Scheduler, Store, LogMailer, FakeScan, Monitor]:
    store, mailer, scan = Store(), LogMailer(), FakeScan(reports)
    m = store.create_monitor("example.com", "owner@example.com", Frequency.WEEKLY, now=0)
    store.confirm_monitor(m.id, now=0)
    sched = Scheduler(
        store=store,
        scan=scan,
        mailer=mailer,
        base_url="https://rs.test",
        report_ttl_s=1000,
        manage_link=lambda mon: f"https://rs.test/m/{mon.id}/tok",
    )
    return sched, store, mailer, scan, m


async def test_first_run_sends_started_email_then_only_alerts_on_regressions() -> None:
    clean, worse = report(), report(finding("headers.csp.missing", Severity.MEDIUM))
    sched, store, mailer, scan, m = make([clean, clean, worse])

    assert await sched.tick(now=1) == 1
    assert scan.calls == [("example.com", True)]
    assert len(mailer.sent) == 1 and "Monitoring example.com: grade A" in mailer.sent[0].subject
    assert "https://rs.test/r/" in mailer.sent[0].body
    assert mailer.sent[0].unsubscribe_url == f"https://rs.test/m/{m.id}/tok/unsubscribe"

    assert await sched.tick(now=2) == 0  # not due yet
    await sched.tick(now=1 + Frequency.WEEKLY.seconds)
    assert len(mailer.sent) == 1  # unchanged: no email

    await sched.tick(now=1 + 2 * Frequency.WEEKLY.seconds)
    assert len(mailer.sent) == 2
    assert "headers.csp.missing" in mailer.sent[1].body
    assert len(store.history(m.id)) == 3


async def test_failures_alert_once_after_threshold() -> None:
    errors: list[Report | Exception] = [OSError("connection refused")] * (FAILURES_BEFORE_ALERT + 1)
    sched, store, mailer, _, m = make(errors)
    for i in range(FAILURES_BEFORE_ALERT + 1):
        await sched.tick(now=i * Frequency.WEEKLY.seconds + 1)
    assert len(mailer.sent) == 1 and "Can't reach example.com" in mailer.sent[0].subject
    got = store.get_monitor(m.id)
    assert got is not None and got.failures == FAILURES_BEFORE_ALERT + 1


@pytest.mark.parametrize("bad", [ValueError("boom"), RuntimeError()])
async def test_one_failing_monitor_does_not_stop_the_tick(bad: Exception) -> None:
    sched, store, mailer, scan, _ = make([bad, report()])
    other = store.create_monitor("other.com", "x@y.co", Frequency.WEEKLY, now=0)
    store.confirm_monitor(other.id, now=0)
    assert await sched.tick(now=1) == 2
    assert len(mailer.sent) == 1 and "other.com" in mailer.sent[0].subject


class BrokenMailer(LogMailer):
    async def send(self, email: Email) -> None:
        raise OSError("smtp down")


async def test_mail_outage_does_not_stop_other_monitors() -> None:
    sched, store, _, scan, _ = make([report(), report()])
    sched.mailer = BrokenMailer()
    other = store.create_monitor("other.com", "x@y.co", Frequency.WEEKLY, now=0)
    store.confirm_monitor(other.id, now=0)
    assert await sched.tick(now=1) == 2
    assert len(scan.calls) == 2
    got = store.get_monitor(other.id)
    assert got is not None and got.last_report_id is not None
