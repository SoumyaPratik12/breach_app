from app.risk.recommendations import (
    recommend_for_finding,
    recommend_for_findings,
)
from app.schemas.scan import ExposureFinding, FindingCategory, FindingSeverity


def make_finding(category, severity):
    return ExposureFinding(
        category=category,
        severity=severity,
        description="Simulated test finding",
        source="Simulated test source",
    )


def test_high_credential_finding_recommends_security_actions():
    finding = make_finding(
        FindingCategory.CREDENTIAL_EXPOSURE,
        FindingSeverity.HIGH,
    )

    result = recommend_for_finding(finding)

    assert result["priority"] == "high"
    assert "credential" in result["title"].lower()
    assert any("multi-factor" in step for step in result["steps"])
    assert result["simulated"] is True
    assert result["verified"] is False
    assert result["advisory_only"] is True


def test_public_profile_finding_recommends_privacy_review():
    finding = make_finding(
        FindingCategory.PUBLIC_PROFILE,
        FindingSeverity.LOW,
    )

    result = recommend_for_finding(finding)

    assert result["priority"] == "low"
    assert any("privacy settings" in step for step in result["steps"])
    assert result["simulated"] is True
    assert result["verified"] is False


def test_medium_credential_finding_recommends_verification():
    finding = make_finding(
        FindingCategory.CREDENTIAL_EXPOSURE,
        FindingSeverity.MEDIUM,
    )

    result = recommend_for_finding(finding)

    assert result["priority"] == "medium"
    assert any("Verify" in step for step in result["steps"])


def test_empty_findings_produce_no_recommendations():
    assert recommend_for_findings([]) == []


def test_recommendations_preserve_finding_order():
    findings = [
        make_finding(
            FindingCategory.PUBLIC_PROFILE,
            FindingSeverity.LOW,
        ),
        make_finding(
            FindingCategory.CREDENTIAL_EXPOSURE,
            FindingSeverity.HIGH,
        ),
    ]

    results = recommend_for_findings(findings)

    assert [result["category"] for result in results] == [
        "public_profile",
        "credential_exposure",
    ]