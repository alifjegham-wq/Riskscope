from riskscope.models import Category, Finding, Report, Severity
from riskscope.scoring import apply_score, grade_for, score_findings


def f(sev: Severity, cat: Category = Category.HEADERS, i: str = "x") -> Finding:
    return Finding(id=i, title=i, severity=sev, category=cat, description="")


def test_clean_scan_is_a() -> None:
    r = apply_score(Report(target="t", kind="website"))
    assert (r.score, r.grade, r.risk_level) == (100, "A", "Low")


def test_repeat_findings_in_one_category_are_discounted() -> None:
    # 8 + 4 + 2 = 14 rather than 24
    assert score_findings([f(Severity.MEDIUM, i=str(n)) for n in range(3)]) == 86


def test_categories_are_independent() -> None:
    assert score_findings([f(Severity.MEDIUM, Category.HEADERS), f(Severity.MEDIUM, Category.EMAIL)]) == 84


def test_critical_caps_at_f() -> None:
    r = apply_score(Report(target="t", kind="website", findings=[f(Severity.CRITICAL)]))
    assert r.score == 49 and r.grade == "F" and r.risk_level == "Critical"


def test_info_is_free() -> None:
    assert score_findings([f(Severity.INFO)] * 10) == 100


def test_grade_boundaries() -> None:
    assert [grade_for(s) for s in (100, 90, 89, 80, 79, 65, 64, 50, 49, 0)] == list("AABBCCDDFF")
