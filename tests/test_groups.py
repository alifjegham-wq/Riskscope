import httpx
from fastapi.testclient import TestClient

from riskscope.checks.headers import SecurityHeadersCheck
from riskscope.config import Settings
from riskscope.models import Report
from riskscope.monitoring import Scheduler, grade_worse
from riskscope.notify import LogMailer
from riskscope.safety import Target
from riskscope.store import Store
from riskscope.web.app import create_app

from .conftest import FakeDns, FakeVulns, public_resolver, site

SECRET = "group-secret"


def mk_report(host: str, grade: str, score: int) -> Report:
    return Report(target=host, kind="website", grade=grade, score=score)


# ---- store -----------------------------------------------------------------


def test_group_membership_crud() -> None:
    store = Store()
    g = store.create_group("Mine", ["a.com", "b.com", "a.com"], now=0)  # last is a duplicate
    assert {m.host for m in store.list_members(g.id)} == {"a.com", "b.com"}

    store.add_members(g.id, ["c.com"], cap=10)
    assert len(store.list_members(g.id)) == 3
    store.add_members(g.id, ["d.com", "e.com"], cap=3)  # already at cap -> no room
    assert len(store.list_members(g.id)) == 3

    store.remove_member(g.id, "a.com")
    assert {m.host for m in store.list_members(g.id)} == {"b.com", "c.com"}

    store.record_member_result(g.id, "b.com", "C", 70)
    b = next(m for m in store.list_members(g.id) if m.host == "b.com")
    assert b.prev_grade == "C" and b.prev_score == 70

    store.delete_group(g.id)
    assert store.get_group(g.id) is None
    assert store.list_members(g.id) == []  # cascade removed members


def test_group_monitoring_scheduling() -> None:
    store = Store()
    g = store.create_group("Mine", ["a.com"], email="o@e.com", now=0)
    assert not g.confirmed and not g.monitoring
    assert store.count_groups_for_email("o@e.com") == 1
    assert store.claim_due_groups(now=100) == []  # unconfirmed never runs

    store.confirm_group(g.id, now=10)
    g2 = store.get_group(g.id)
    assert g2 is not None and g2.confirmed and g2.monitoring

    due = store.claim_due_groups(now=20)
    assert [x.id for x in due] == [g.id]
    assert store.claim_due_groups(now=21) == []  # next run pushed forward

    store.set_group_monitoring(g.id, False)
    off = store.get_group(g.id)
    assert off is not None and not off.monitoring


def test_set_group_monitoring_requires_confirmation() -> None:
    store = Store()
    g = store.create_group("Mine", ["a.com"], email="o@e.com", now=0)
    store.set_group_monitoring(g.id, True, now=0)  # not confirmed yet
    assert store.get_group(g.id).monitoring is False  # type: ignore[union-attr]


# ---- regression detection & scheduler --------------------------------------


def test_grade_worse() -> None:
    assert grade_worse("A", 95, "B", 80)  # lower grade
    assert grade_worse("B", 80, "B", 74)  # same grade, clear score drop
    assert not grade_worse("B", 80, "B", 78)  # small drop, not flagged
    assert not grade_worse("C", 60, "B", 85)  # improved
    assert not grade_worse("A", 100, "A", 100)


def _sched(store: Store, mailer: LogMailer, reports: dict[str, Report]) -> Scheduler:
    async def scan(target: Target, active: bool) -> Report:
        return reports[target.host]

    return Scheduler(
        store=store,
        scan=scan,
        mailer=mailer,
        base_url="https://rs.test",
        report_ttl_s=1000,
        manage_link=lambda m: "https://rs.test/m",
        group_manage_link=lambda g: f"https://rs.test/g/{g.id}/tok",
    )


async def test_run_group_emails_only_on_regression() -> None:
    store, mailer = Store(), LogMailer()
    g = store.create_group("Mine", ["a.com", "b.com"], email="o@e.com", now=0)
    store.confirm_group(g.id, now=0)
    store.record_member_result(g.id, "a.com", "A", 95)
    store.record_member_result(g.id, "b.com", "B", 82)
    reports = {"a.com": mk_report("a.com", "C", 64), "b.com": mk_report("b.com", "B", 82)}
    group = store.get_group(g.id)
    assert group is not None
    await _sched(store, mailer, reports).run_group(group)

    assert len(mailer.sent) == 1
    body = mailer.sent[0].body
    assert "a.com" in body and "b.com" not in body  # only a.com got worse
    members = {m.host: m for m in store.list_members(g.id)}
    assert members["a.com"].prev_grade == "C" and members["b.com"].prev_grade == "B"


async def test_run_group_first_run_sets_baseline_without_email() -> None:
    store, mailer = Store(), LogMailer()
    g = store.create_group("Mine", ["a.com"], email="o@e.com", now=0)
    store.confirm_group(g.id, now=0)
    group = store.get_group(g.id)
    assert group is not None
    await _sched(store, mailer, {"a.com": mk_report("a.com", "F", 40)}).run_group(group)
    assert mailer.sent == []  # no previous grade -> no alert
    assert store.list_members(g.id)[0].prev_grade == "F"


# ---- web -------------------------------------------------------------------


def _client(*, storage: bool = True) -> TestClient:
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(site({"/": httpx.Response(200, text="hi")})))
    app = create_app(
        Settings(
            verify_secret=SECRET,
            database_path=":memory:",
            persistent_storage=storage,
            scheduler_enabled=False,
        ),
        http=upstream,
        vulns=FakeVulns(),
        resolver=public_resolver,
        dns=FakeDns(),
        checks=[SecurityHeadersCheck()],
        mailer=LogMailer(),
    )
    return TestClient(app)


def test_groups_require_persistent_storage() -> None:
    with _client(storage=False) as c:
        assert c.get("/groups").status_code == 503


def test_group_create_manage_add_remove_delete() -> None:
    with _client() as c:
        created = c.post("/groups", data={"name": "Mine", "assets": "a.com\nb.com"}, follow_redirects=False)
        assert created.status_code == 303
        loc = created.headers["location"]
        assert loc.startswith("/g/")

        manage = c.get(loc)
        assert manage.status_code == 200
        assert "Mine" in manage.text
        assert "<code>a.com</code>" in manage.text and "<code>b.com</code>" in manage.text

        c.post(loc + "/add", data={"assets": "c.com"}, follow_redirects=False)
        assert "<code>c.com</code>" in c.get(loc).text

        c.post(loc + "/remove", data={"host": "b.com"}, follow_redirects=False)
        assert "<code>b.com</code>" not in c.get(loc).text
        assert "<code>a.com</code>" in c.get(loc).text

        deleted = c.post(loc + "/delete")
        assert "deleted" in deleted.text.lower()
        assert c.get(loc).status_code == 404


def test_group_manage_rejects_bad_token() -> None:
    with _client() as c:
        loc = c.post("/groups", data={"name": "G", "assets": "a.com"}, follow_redirects=False).headers["location"]
        gid = loc.split("/")[2]
        assert c.get(f"/g/{gid}/wrongtoken").status_code == 404
