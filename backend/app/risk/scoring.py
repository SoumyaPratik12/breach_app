"""Deterministic risk scoring for exposure findings.

Scores are product heuristics, not validated security-risk measurements.
"""

from collections import Counter
from typing import Sequence

from app.schemas.scan import ExposureFinding, FindingSeverity


SEVERITY_POINTS = {
    FindingSeverity.LOW: 5,
    FindingSeverity.MEDIUM: 15,
    FindingSeverity.HIGH: 25,
}


def score_finding(finding: ExposureFinding) -> int:
    """Return the configured score for one finding."""
    return SEVERITY_POINTS[finding.severity]


def risk_level(score: int) -> str:
    """Map a score from 0 to 100 to a human-readable risk level."""
    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")

    if score == 0:
        return "none"
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def summarize_findings(findings: Sequence[ExposureFinding]) -> dict:
    """Return a capped risk score, level, counts, and prioritized findings."""
    severity_counts = Counter(finding.severity.value for finding in findings)

    total_score = min(
        100,
        sum(score_finding(finding) for finding in findings),
    )

    prioritized = sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_POINTS[finding.severity],
            finding.category.value
            if hasattr(finding.category, "value")
            else str(finding.category),
        ),
    )

    return {
        "risk_score": total_score,
        "risk_level": risk_level(total_score),
        "total_findings": len(findings),
        "severity_counts": {
            severity.value: severity_counts.get(severity.value, 0)
            for severity in FindingSeverity
        },
        "prioritized_findings": prioritized,
    }