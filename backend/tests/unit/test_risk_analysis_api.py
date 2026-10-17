from datetime import datetime, timezone

import pytest

from app.models import (
    ExposureScan,
    Identifier,
    ScanStatus,
    VerificationStatus,
)
from app.schemas.scan import ExposureFinding, FindingCategory, FindingSeverity


def register_and_authenticate(client, email):
    response = client.post(
        "/auth/register",
        json={"email": email, "password": "TestPassword123!"},
    )
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def create_identifier(client, headers, email):
    response = client.post(
        "/identifiers",
        headers=headers,
        json={"type": "email", "value": email},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def verify_identifier(db_session, identifier_id):
    identifier = db_session.get(Identifier, identifier_id)
    assert identifier is not None
    identifier.verification_status = VerificationStatus.VERIFIED
    identifier.verified_at = datetime.now(timezone.utc)
    db_session.commit()


def add_completed_scan(
    db_session,
    user_id,
    identifier_id,
    severities=(),
    *,
    simulated=True,
):
    findings = [
        ExposureFinding(
            category=FindingCategory.CREDENTIAL_EXPOSURE,
            severity=severity,
            description="Simulated test finding",
            source="Simulated test source",
        ).model_dump(mode="json")
        for severity in severities
    ]
    scan = ExposureScan(
        user_id=user_id,
        identifier_id=identifier_id,
        status=ScanStatus.COMPLETED,
        is_simulated=simulated,
        findings=findings,
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    db_session.commit()
    return scan


def test_risk_analysis_requires_authentication(client):
    response = client.get("/risk-analysis")

    assert response.status_code == 401


def test_risk_analysis_only_uses_current_users_scans(
    client,
    db_session,
):
    owner_headers = register_and_authenticate(
        client,
        "risk-owner@example.com",
    )
    owner_identifier_id = create_identifier(
        client,
        owner_headers,
        "risk-owner-identifier@example.com",
    )
    verify_identifier(db_session, owner_identifier_id)
    add_completed_scan(
        db_session,
        db_session.get(Identifier, owner_identifier_id).user_id,
        owner_identifier_id,
        [FindingSeverity.LOW],
    )

    other_headers = register_and_authenticate(
        client,
        "risk-other@example.com",
    )
    other_identifier_id = create_identifier(
        client,
        other_headers,
        "risk-other-identifier@example.com",
    )
    verify_identifier(db_session, other_identifier_id)
    other_user_id = db_session.get(Identifier, other_identifier_id).user_id
    add_completed_scan(
        db_session,
        other_user_id,
        other_identifier_id,
        [FindingSeverity.HIGH] * 5,
    )

    response = client.get("/risk-analysis", headers=owner_headers)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["scans_analyzed"] == 1
    assert data["risk_score"] == 5
    assert data["risk_category"] == "low"
    assert data["contributing_factors"] == [
        {"category": "credential_exposure", "severity": "low", "count": 1}
    ]
    assert "risk-other-identifier@example.com" not in response.text


def test_risk_analysis_excludes_scans_for_unverified_identifiers(
    client,
    db_session,
):
    headers = register_and_authenticate(
        client,
        "risk-unverified@example.com",
    )
    identifier_id = create_identifier(
        client,
        headers,
        "risk-pending@example.com",
    )
    identifier = db_session.get(Identifier, identifier_id)
    assert identifier is not None
    add_completed_scan(
        db_session,
        identifier.user_id,
        identifier_id,
        [FindingSeverity.HIGH],
    )

    response = client.get("/risk-analysis", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "insufficient_data"
    assert data["risk_score"] is None
    assert data["risk_category"] is None
    assert data["contributing_factors"] == []
    assert data["recommendations"] == []
    assert data["scans_analyzed"] == 0


def test_risk_analysis_reports_insufficient_data_without_completed_scans(
    client,
    db_session,
):
    headers = register_and_authenticate(
        client,
        "risk-no-scans@example.com",
    )
    identifier_id = create_identifier(
        client,
        headers,
        "risk-no-scans-identifier@example.com",
    )
    verify_identifier(db_session, identifier_id)
    identifier = db_session.get(Identifier, identifier_id)
    assert identifier is not None
    db_session.add(
        ExposureScan(
            user_id=identifier.user_id,
            identifier_id=identifier_id,
            status=ScanStatus.RUNNING,
            is_simulated=True,
            findings=[],
        )
    )
    db_session.commit()

    response = client.get("/risk-analysis", headers=headers)

    assert response.status_code == 200
    assert response.json()["status"] == "insufficient_data"
    assert response.json()["scans_analyzed"] == 0
    assert response.json()["risk_score"] is None


def test_risk_analysis_marks_simulated_findings_and_advisories(
    client,
    db_session,
):
    headers = register_and_authenticate(
        client,
        "risk-simulated@example.com",
    )
    identifier_id = create_identifier(
        client,
        headers,
        "risk-simulated-identifier@example.com",
    )
    verify_identifier(db_session, identifier_id)
    identifier = db_session.get(Identifier, identifier_id)
    assert identifier is not None
    add_completed_scan(
        db_session,
        identifier.user_id,
        identifier_id,
        [FindingSeverity.HIGH, FindingSeverity.LOW],
    )

    response = client.get("/risk-analysis", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["simulated"] is True
    assert data["risk_score"] == 30
    assert 0 < len(data["recommendations"]) <= 3
    assert all(item["simulated"] is True for item in data["recommendations"])
    assert all(item["verified"] is False for item in data["recommendations"])
    assert all(item["advisory_only"] is True for item in data["recommendations"])
    assert "heuristic" in data["methodology"].lower()
    assert "not a trained or validated AI" in " ".join(data["limitations"])


@pytest.mark.parametrize(
    ("low_findings", "expected_score", "expected_category"),
    [
        (0, 0, "none"),
        (1, 5, "low"),
        (4, 20, "low"),
        (5, 25, "medium"),
        (9, 45, "medium"),
        (10, 50, "high"),
        (14, 70, "high"),
        (15, 75, "critical"),
        (25, 100, "critical"),
        (30, 100, "critical"),
    ],
)
def test_risk_analysis_score_category_boundaries(
    client,
    db_session,
    low_findings,
    expected_score,
    expected_category,
):
    headers = register_and_authenticate(
        client,
        f"risk-boundary-{low_findings}@example.com",
    )
    identifier_id = create_identifier(
        client,
        headers,
        f"risk-boundary-identifier-{low_findings}@example.com",
    )
    verify_identifier(db_session, identifier_id)
    identifier = db_session.get(Identifier, identifier_id)
    assert identifier is not None
    add_completed_scan(
        db_session,
        identifier.user_id,
        identifier_id,
        [FindingSeverity.LOW] * low_findings,
    )

    response = client.get("/risk-analysis", headers=headers)

    assert response.status_code == 200
    assert response.json()["risk_score"] == expected_score
    assert response.json()["risk_category"] == expected_category
