"""Posture scoring: fold findings into a 0-100 score and an A-F grade.

Mozilla-Observatory-flavoured and deliberately simple: start at 100, subtract per
finding by severity, and map to a letter (A+ requires no high/medium findings).
The grade is a configuration-quality signal, **not** proof of security. Pure —
reads the result's findings, performs no I/O and invents nothing.

Severity weighting: high and medium findings dominate the grade. Low-severity
findings are minor hygiene items — each costs little and their **combined** impact
is capped (``_MAX_TOTAL_PENALTY``), so a long tail of lows cannot sink the grade the
way one real (high/medium) issue should.
"""
from __future__ import annotations

from typing import Any, Dict

_PENALTY = {"high": 35, "medium": 15, "low": 2, "info": 0}
# Aggregate cap per severity: lows are minor, so all of them together can subtract at
# most this many points (whether there are 3 or 30).
_MAX_TOTAL_PENALTY = {"low": 10}

GRADE_COLORS = {"A+": "#1e7e34", "A": "#2e9e4f", "B": "#c9a227",
                "C": "#e67e22", "D": "#d35400", "F": "#c0392b"}


def _counts(findings) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings or []:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def grade_for(score: int, counts: Dict[str, int]) -> str:
    if score >= 95 and not counts.get("high") and not counts.get("medium"):
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_score(result: Any) -> Dict[str, Any]:
    d = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    counts = _counts(d.get("findings"))
    score = 100
    for sev, n in counts.items():
        penalty = _PENALTY.get(sev, 0) * n
        cap = _MAX_TOTAL_PENALTY.get(sev)
        if cap is not None:
            penalty = min(penalty, cap)
        score -= penalty
    score = max(0, min(100, score))
    return {"score": score, "grade": grade_for(score, counts),
            "breakdown": {k: counts.get(k, 0) for k in ("high", "medium", "low", "info")},
            "note": "Configuration-quality signal, not a guarantee of security."}
