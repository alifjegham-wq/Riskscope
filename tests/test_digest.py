import sqlite3
from pathlib import Path

from riskscope.models import Category, Finding, Report, Severity
from riskscope.monitoring import DIGEST_TOP_ISSUES, Scheduler, digest_email
from riskscope.notify import LogMailer
from riskscope.safety import Target
from riskscope.scoring import apply_score
from riskscope.store import DIGEST_PERIOD_S, Frequency, Monitor, Store

DAY = 86_400


def finding(fid: str, sev: Severity) -> Finding:
    return Finding(id=fid, title=f"title {fid}", severity=sev, category=Category.HEADERS, description="")


def report(*findings: Finding) -> Report:
    return apply_score(Report(target="example.com", kind="website", findings=list(findings)))


def monitor(store: Store, digest: bool = True, now: float = 0) -> Monitor:
    m = store.create_monitor("example.com", "owner@example.com", Frequency.DAILY, now=now, digest=digest)
    store.confirm_monitor(m.id, now=now)
    got = store.get_monitor(m.id)
    assert got is not None
    return got


# ---- store -----------------------------------------------------------------


def test_old_database_is_migrated(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE monitors (id TEXT PRIMARY KEY, target TEXT NOT NULL, email TEXT NOT NULL,"
        " frequency TEXT NOT NULL,"
        " confirmed INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, next_run_at REAL NOT NULL,"
        " last_report_id TEXT, failures INTEGER NOT NULL DEFAULT 0);"
        "INSERT INTO monitors (id, target, email, frequency, confirmed, created_at, next_run_at)"
        " VALUES ('m1', 'example.com', 'a@b.co', 'weekly', 1, 0, 0);"
    )
    db.commit()
    db.close()
    store = Store(str(path))
    m = store.get_monitor("m1")
    assert m is not None and m.digest is False and m.next_digest_at is None
    Store(str(path))  # migrating twice is a no-op


def test_digest_schedule_starts_a_week_after_confirmation() -> None:
    store = Store()
    m = monitor(store, now=100)
    assert m.next_digest_at == 100 + DIGEST_PERIOD_S
    assert store.claim_due_digests(now=100 + DIGEST_PERIOD_S - 1) == []
    [due] = store.claim_due_digests(now=100 + DIGEST_PERIOD_S)
    assert due.id == m.id
    assert store.claim_due_digests(now=100 + DIGEST_PERIOD_S + 1) == []  # already claimed
    got = store.get_monitor(m.id)
    assert got is not None and got.next_digest_at == 100 + 2 * DIGEST_PERIOD_S


def test_digest_off_or_unconfirmed_is_never_due() -> None:
    store = Store()
    monitor(store, digest=False)
    pending = store.create_monitor("other.com", "a@b.co", Frequency.WEEKLY, now=0, digest=True)
    assert pending.next_digest_at is None
    assert store.claim_due_digests(now=10 * DIGEST_PERIOD_S) == []


def test_toggle_digest() -> None:
    store = Store()
    m = monitor(store, digest=False)
    store.set_digest(m.id, True, now=50)
    on = store.get_monitor(m.id)
    assert on is not None and on.digest and on.next_digest_at == 50 + DIGEST_PERIOD_S
    store.set_digest(m.id, False)
    off = store.get_monitor(m.id)
    assert off is not None and not off.digest and off.next_digest_at is None


def test_reports_between_and_baseline() -> None:
    store = Store()
    m = monitor(store)
    ids = [store.save_report(report(), 100 * DAY, monitor_id=m.id, now=t)[0] for t in (1 * DAY, 8 * DAY, 10 * DAY)]
    week = store.reports_between(m.id, 7 * DAY, 14 * DAY)
    assert [r.id for r in week] == ids[1:]
    base = store.report_before(m.id, 7 * DAY)
    assert base is not None and base.id == ids[0]
    assert store.report_before(m.id, 0) is None


# ---- email content -----------------------------------------------------------


def test_digest_email_trend_new_fixed_and_todo() -> None:
    store = Store()
    m = monitor(store)
    baseline = report(finding("old", Severity.MEDIUM), finding("still", Severity.HIGH))
    latest = report(finding("still", Severity.HIGH), finding("new", Severity.MEDIUM), finding("i", Severity.INFO))
    email = digest_email(m, [report(), latest], baseline, "https://rs.test/r/x", "https://rs.test/m/1/t")
    body = email.body
    assert email.subject == f"[riskscope] Weekly summary for example.com: grade {latest.grade}"
    assert "2 scans this week" in body
    assert "New this week:\n  - [MEDIUM] title new" in body
    assert "Fixed this week, nice work:\n  - [MEDIUM] title old" in body
    assert "Top things to fix next:\n  - [HIGH] title still" in body and "title i" not in body  # info is left out
    assert "https://rs.test/r/x" in body
    assert email.unsubscribe_url == "https://rs.test/m/1/t/unsubscribe"


def test_digest_email_grade_direction() -> None:
    store = Store()
    m = monitor(store)
    good, bad = report(), report(finding("a", Severity.CRITICAL))
    assert f"(up from {bad.grade} a week ago)" in digest_email(m, [good], bad, None, "u").body
    assert f"(down from {good.grade} a week ago)" in digest_email(m, [bad], good, None, "u").body
    assert "(unchanged from A a week ago)" in digest_email(m, [good], good, None, "u").body
    assert "(first week of monitoring)" in digest_email(m, [good], None, None, "u").body
    assert "No open issues" in digest_email(m, [good], None, None, "u").body


def test_digest_email_caps_todo_list() -> None:
    store = Store()
    m = monitor(store)
    many = report(*(finding(f"f{i}", Severity.LOW) for i in range(DIGEST_TOP_ISSUES + 3)))
    assert "... and 3 more in the full report" in digest_email(m, [many], None, None, "u").body


def test_digest_email_without_scans() -> None:
    store = Store()
    m = monitor(store)
    store.record_run(m.id, None)
    store.record_run(m.id, None)
    failing = store.get_monitor(m.id)
    assert failing is not None
    email = digest_email(failing, [], None, None, "u")
    assert email.subject.endswith(": no scans") and "last 2 scan attempts couldn't reach" in email.body


# ---- scheduler ---------------------------------------------------------------


class NoScan:
    async def __call__(self, target: Target, want_active: bool) -> Report:
        raise AssertionError("no scan expected")


async def test_tick_sends_digest_only_when_due_and_opted_in() -> None:
    store, mailer = Store(), LogMailer()
    m = monitor(store, now=0)
    monitor_off = store.create_monitor("quiet.com", "x@y.co", Frequency.DAILY, now=0)
    store.confirm_monitor(monitor_off.id, now=0)
    # Push both monitors' scans far into the future so only digests are in play.
    store._db.execute("UPDATE monitors SET next_run_at = ?", (1e12,))
    store.save_report(report(), 100 * DAY, monitor_id=m.id, now=3 * DAY)
    sched = Scheduler(
        store,
        NoScan(),
        mailer,
        "https://rs.test",
        100 * DAY,
        lambda mon: f"https://rs.test/m/{mon.id}/t",
        lambda g: f"https://rs.test/g/{g.id}/t",
    )

    await sched.tick(now=DIGEST_PERIOD_S - 1)
    assert mailer.sent == []
    await sched.tick(now=DIGEST_PERIOD_S)
    [email] = mailer.sent
    assert email.to == "owner@example.com" and "Weekly summary for example.com" in email.subject
    assert "1 scan this week" in email.body and "https://rs.test/r/" in email.body
    await sched.tick(now=DIGEST_PERIOD_S + 60)
    assert len(mailer.sent) == 1  # not again until next week


def test_started_email_mentions_digest() -> None:
    from riskscope.monitoring import started_email

    store = Store()
    on, off = monitor(store, digest=True), monitor(store, digest=False)
    assert "weekly summary" in started_email(on, report(), "r", "m").body
    assert "weekly summary" not in started_email(off, report(), "r", "m").body
