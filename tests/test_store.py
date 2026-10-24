from riskscope.models import Report
from riskscope.store import Frequency, Store, check_monitor_token, monitor_token


def report(grade: str = "B") -> Report:
    return Report(target="example.com", kind="website", grade=grade, score=85)


def test_save_get_and_expire() -> None:
    store = Store()
    rid, token = store.save_report(report(), ttl_s=100, now=1000)
    assert len(rid) >= 20 and len(token) >= 30
    got = store.get_report(rid, now=1050)
    assert got is not None and got.report.grade == "B" and got.expires_at == 1100
    assert store.get_report(rid, now=1100) is None
    assert store.get_report(rid, now=5000, allow_expired=True) is not None
    assert store.purge_expired(now=1100) == 1
    assert store.get_report(rid, allow_expired=True) is None


def test_delete_token_is_checked_and_not_stored_in_clear() -> None:
    store = Store()
    rid, token = store.save_report(report(), ttl_s=100)
    assert store.check_report_token(rid, token)
    assert not store.check_report_token(rid, token + "x")
    assert not store.check_report_token("nope", token)
    dump = "\n".join(store._db.iterdump())
    assert token not in dump


def test_monitor_tokens_are_hmac_bound_to_id_and_secret() -> None:
    t = monitor_token("s1", "m1")
    assert check_monitor_token("s1", "m1", t)
    assert not check_monitor_token("s2", "m1", t) and not check_monitor_token("s1", "m2", t)


def test_claim_due_only_returns_confirmed_and_advances_schedule() -> None:
    store = Store()
    m = store.create_monitor("example.com", "Me@Example.com", Frequency.DAILY, now=0)
    assert m.email == "me@example.com"
    assert store.claim_due(now=10) == []  # unconfirmed
    store.confirm_monitor(m.id, now=10)
    [due] = store.claim_due(now=10)
    assert due.id == m.id
    assert store.claim_due(now=11) == []  # already claimed
    assert [x.id for x in store.claim_due(now=10 + 86_400)] == [m.id]


def test_history_and_cascade_delete() -> None:
    store = Store()
    m = store.create_monitor("example.com", "a@b.co", Frequency.WEEKLY)
    r1, _ = store.save_report(report("C"), 100, monitor_id=m.id, now=1)
    r2, _ = store.save_report(report("A"), 100, monitor_id=m.id, now=2)
    store.record_run(m.id, r2)
    assert [h.grade for h in store.history(m.id)] == ["A", "C"]
    store.record_run(m.id, None)
    got = store.get_monitor(m.id)
    assert got is not None and got.failures == 1 and got.last_report_id == r2
    store.delete_monitor(m.id)
    assert store.get_report(r1, allow_expired=True) is None


def test_purge_keeps_monitor_baseline() -> None:
    store = Store()
    m = store.create_monitor("example.com", "a@b.co", Frequency.WEEKLY)
    rid, _ = store.save_report(report(), 10, monitor_id=m.id, now=0)
    store.record_run(m.id, rid)
    assert store.purge_expired(now=100) == 0


def test_unconfirmed_cleanup() -> None:
    store = Store()
    old = store.create_monitor("a.com", "a@b.co", Frequency.WEEKLY, now=0)
    keep = store.create_monitor("b.com", "a@b.co", Frequency.WEEKLY, now=0)
    store.confirm_monitor(keep.id)
    assert store.delete_unconfirmed(older_than_s=100, now=200) == 1
    assert store.get_monitor(old.id) is None and store.get_monitor(keep.id) is not None
