import pytest

from app.risk.scoring import risk_level, score_finding, summarize_findings
from app.schemas.scan import ExposureFinding, FindingSeverity


def make_finding(severity, category="credential_exposure"):
    return ExposureFinding(
        category=category,
        severity=severity,
        description="Simulated test finding",
        source="simulated",
        simulated=True,
        verified=False,
    )


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (FindingSeverity.LOW, 5),
        (FindingSeverity.MEDIUM, 15),
        (FindingSeverity.HIGH, 25),
    ],
)
def test_score_finding(severity, expected):
    assert score_finding(make_finding(severity)) == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "none"),
        (1, "low"),
        (24, "low"),
        (25, "medium"),
        (49, "medium"),
        (50, "high"),
        (74, "high"),
        (75, "critical"),
        (100, "critical"),
    ],
)
def test_risk_level_boundaries(score, expected):
    assert risk_level(score) == expected


@pytest.mark.parametrize("score", [-1, 101])
def test_risk_level_rejects_out_of_range_scores(score):
    with pytest.raises(ValueError):
        risk_level(score)


def test_empty_findings_have_no_risk():
    summary = summarize_findings([])

    assert summary["risk_score"] == 0
    assert summary["risk_level"] == "none"
    assert summary["total_findings"] == 0
    assert summary["prioritized_findings"] == []
    assert summary["severity_counts"] == {
        "low": 0,
        "medium": 0,
        "high": 0,
    }


def test_summary_counts_and_prioritizes_findings():
    findings = [
        make_finding(FindingSeverity.LOW, "public_profile"),
        make_finding(FindingSeverity.HIGH, "credential_exposure"),
        make_finding(FindingSeverity.MEDIUM, "credential_exposure"),
    ]

    summary = summarize_findings(findings)

    assert summary["risk_score"] == 45
    assert summary["risk_level"] == "medium"
    assert summary["total_findings"] == 3
    assert summary["severity_counts"] == {
        "low": 1,
        "medium": 1,
        "high": 1,
    }
    assert [
        finding.severity for finding in summary["prioritized_findings"]
    ] == [
        FindingSeverity.HIGH,
        FindingSeverity.MEDIUM,
        FindingSeverity.LOW,
    ]


def test_score_is_capped_at_100():
    findings = [make_finding(FindingSeverity.HIGH) for _ in range(5)]

    summary = summarize_findings(findings)

    assert summary["risk_score"] == 100
    assert summary["risk_level"] == "critical"


def test_simulated_findings_remain_labeled_as_simulated():
    summary = summarize_findings([make_finding(FindingSeverity.HIGH)])

    finding = summary["prioritized_findings"][0]
    assert finding.simulated is True
    assert finding.verified is False