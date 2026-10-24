"""Turn findings into a 0-100 score, a letter grade and a risk level.

The model is deliberately simple and explainable (it is shown on the report):

* every finding subtracts a fixed weight for its severity;
* repeated findings in the same category are discounted (the 2nd counts half,
  the 3rd onward a quarter) so one noisy area cannot dominate the grade;
* any critical finding caps the score at 49 (grade F) because a single critical
  issue is usually enough for a compromise.
"""

from __future__ import annotations

from collections import defaultdict

from .models import Finding, Report, Severity

WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

_REPEAT_FACTORS = (1.0, 0.5)
_TAIL_FACTOR = 0.25
CRITICAL_CAP = 49

GRADES = ((90, "A"), (80, "B"), (65, "C"), (50, "D"), (0, "F"))


def score_findings(findings: list[Finding]) -> int:
    by_category: dict[str, list[float]] = defaultdict(list)
    for f in findings:
        by_category[f.category].append(WEIGHTS[f.severity])

    penalty = 0.0
    for weights in by_category.values():
        for i, w in enumerate(sorted(weights, reverse=True)):
            factor = _REPEAT_FACTORS[i] if i < len(_REPEAT_FACTORS) else _TAIL_FACTOR
            penalty += w * factor

    score = max(0, round(100 - penalty))
    if any(f.severity is Severity.CRITICAL for f in findings):
        score = min(score, CRITICAL_CAP)
    return score


def grade_for(score: int) -> str:
    for floor, letter in GRADES:
        if score >= floor:
            return letter
    return "F"


def risk_level_for(score: int) -> str:
    if score >= 90:
        return "Low"
    if score >= 65:
        return "Moderate"
    if score >= 50:
        return "High"
    return "Critical"


def apply_score(report: Report) -> Report:
    report.score = score_findings(report.findings)
    report.grade = grade_for(report.score)
    report.risk_level = risk_level_for(report.score)
    return report
