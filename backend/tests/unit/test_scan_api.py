from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.config.settings import settings
from app.models import (
    ExposureScan,
    Identifier,
    ScanStatus,
    User,
    VerificationStatus,
)
from app.services.scan_provider import ScanProviderError
from app.services.scan_service import start_scan


@pytest.fixture(autouse=True)
def reset_scan_rate_limiter():
    from app.services.scan_service import scan_rate_limiter

    scan_rate_limiter.reset()
    yield
    scan_rate_limiter.reset()


def register_and_authenticate(client, email):
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "TestPassword123!",
        },
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


def test_unverified_identifier_cannot_be_scanned(
    client,
    db_session,
):
    headers = register_and_authenticate(client, "scan-pending@example.com")
    identifier_id = create_identifier(
        client,
        headers,
        "person@example.com",
    )

    response = client.post(
        f"/identifiers/{identifier_id}/scans",
        headers=headers,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "Identifier must be verified before scanning"
    )
    assert db_session.query(ExposureScan).count() == 0


def test_scan_results_are_simulated_and_persisted(
    client,
    db_session,
):
    headers = register_and_authenticate(client, "scan-owner@example.com")
    identifier_id = create_identifier(
        client,
        headers,
        "person@example.com",
    )
    verify_identifier(db_session, identifier_id)

    response = client.post(
        f"/identifiers/{identifier_id}/scans",
        headers=headers,
    )

    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["status"] == "completed"
    assert scan["is_simulated"] is True
    assert scan["error_code"] is None
    assert len(scan["findings"]) == 2
    assert all(item["simulated"] is True for item in scan["findings"])
    assert all(item["verified"] is False for item in scan["findings"])
    assert all("Simulated" in item["source"] for item in scan["findings"])
    assert "person@example.com" not in response.text

    persisted = db_session.get(ExposureScan, scan["id"])
    assert persisted is not None
    assert persisted.user_id
    assert persisted.identifier_id == identifier_id
    assert persisted.status == ScanStatus.COMPLETED
    assert persisted.started_at is not None
    assert persisted.completed_at is not None


def test_each_scan_submission_creates_a_separate_record(
    client,
    db_session,
):
    headers = register_and_authenticate(client, "scan-repeat@example.com")
    identifier_id = create_identifier(
        client,
        headers,
        "person@example.com",
    )
    verify_identifier(db_session, identifier_id)

    first = client.post(
        f"/identifiers/{identifier_id}/scans",
        headers=headers,
    )
    second = client.post(
        f"/identifiers/{identifier_id}/scans",
        headers=headers,
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["id"] != second.json()["id"]
    assert db_session.query(ExposureScan).count() == 2


def test_user_cannot_scan_another_users_identifier(client):
    owner_headers = register_and_authenticate(
        client,
        "scan-other-owner@example.com",
    )
    identifier_id = create_identifier(
        client,
        owner_headers,
        "person@example.com",
    )

    other_headers = register_and_authenticate(
        client,
        "scan-other-user@example.com",
    )
    response = client.post(
        f"/identifiers/{identifier_id}/scans",
        headers=other_headers,
    )

    assert response.status_code == 404


def test_user_cannot_read_another_users_scan(client, db_session):
    owner_headers = register_and_authenticate(
        client,
        "scan-read-owner@example.com",
    )
    identifier_id = create_identifier(
        client,
        owner_headers,
        "person@example.com",
    )
    verify_identifier(db_session, identifier_id)
    scan_response = client.post(
        f"/identifiers/{identifier_id}/scans",
        headers=owner_headers,
    )
    scan_id = scan_response.json()["id"]

    other_headers = register_and_authenticate(
        client,
        "scan-read-other@example.com",
    )
    response = client.get(
        f"/scans/{scan_id}",
        headers=other_headers,
    )

    assert response.status_code == 404


def test_provider_failure_is_persisted_without_provider_details(
    client,
    db_session,
    monkeypatch,
):
    from app.api import scans as scans_api

    class FailingProvider:
        def scan(self):
            raise ScanProviderError("sensitive provider diagnostic")

    monkeypatch.setattr(
        scans_api,
        "simulated_scan_provider",
        FailingProvider(),
    )
    headers = register_and_authenticate(client, "scan-fail@example.com")
    identifier_id = create_identifier(
        client,
        headers,
        "person@example.com",
    )
    verify_identifier(db_session, identifier_id)

    response = client.post(
        f"/identifiers/{identifier_id}/scans",
        headers=headers,
    )

    assert response.status_code == 201, response.text
    assert response.json()["status"] == "failed"
    assert response.json()["error_code"] == "provider_error"
    assert response.json()["findings"] == []
    assert "sensitive provider diagnostic" not in response.text
    persisted = db_session.get(ExposureScan, response.json()["id"])
    assert persisted is not None
    assert persisted.status == ScanStatus.FAILED


def test_scan_requests_are_rate_limited_per_user(client, db_session):
    headers = register_and_authenticate(client, "scan-limit@example.com")
    identifier_id = create_identifier(
        client,
        headers,
        "person@example.com",
    )
    verify_identifier(db_session, identifier_id)

    for _ in range(settings.scan_rate_limit_attempts):
        response = client.post(
            f"/identifiers/{identifier_id}/scans",
            headers=headers,
        )
        assert response.status_code == 201

    response = client.post(
        f"/identifiers/{identifier_id}/scans",
        headers=headers,
    )

    assert response.status_code == 429
    assert response.headers["retry-after"] == str(
        settings.scan_rate_limit_window_seconds
    )
    assert db_session.query(ExposureScan).count() == (
        settings.scan_rate_limit_attempts
    )


def test_unexpected_provider_failure_does_not_leak_details(
    client,
    db_session,
    monkeypatch,
):
    from app.api import scans as scans_api

    class UnexpectedFailingProvider:
        def scan(self):
            raise RuntimeError("sensitive internal diagnostic")

    monkeypatch.setattr(
        scans_api,
        "simulated_scan_provider",
        UnexpectedFailingProvider(),
    )
    headers = register_and_authenticate(
        client,
        "scan-unexpected-failure@example.com",
    )
    identifier_id = create_identifier(
        client,
        headers,
        "person@example.com",
    )
    verify_identifier(db_session, identifier_id)
    response = client.post(
        f"/identifiers/{identifier_id}/scans",
        headers=headers,
    )

    assert response.status_code == 201
    assert response.json()["status"] == "failed"


def test_final_scan_commit_failure_rolls_back_and_leaves_scan_recoverable(
    db_session,
    monkeypatch,
):
    user = User(
        email="scan-commit-failure@example.com",
        password_hash="test-hash",
    )
    db_session.add(user)
    db_session.flush()
    identifier = Identifier(
        user_id=user.id,
        type="email",
        value_hmac="scan-commit-failure-hmac",
        display_value="encrypted-test-value",
        verification_status=VerificationStatus.VERIFIED,
        verified_at=datetime.now(timezone.utc),
    )
    db_session.add(identifier)
    db_session.commit()

    original_commit = db_session.commit
    original_rollback = db_session.rollback
    commit_count = 0
    rollback_count = 0

    def fail_final_commit():
        nonlocal commit_count
        commit_count += 1
        if commit_count == 3:
            raise SQLAlchemyError("simulated commit failure")
        original_commit()

    def track_rollback():
        nonlocal rollback_count
        rollback_count += 1
        original_rollback()

    monkeypatch.setattr(db_session, "commit", fail_final_commit)
    monkeypatch.setattr(db_session, "rollback", track_rollback)

    with pytest.raises(SQLAlchemyError, match="simulated commit failure"):
        start_scan(
            db_session,
            user.id,
            identifier.id,
        )

    assert commit_count == 3
    assert rollback_count == 1
    db_session.expire_all()
    persisted_scan = (
        db_session.query(ExposureScan)
        .filter(ExposureScan.identifier_id == identifier.id)
        .one()
    )
    assert persisted_scan.status == ScanStatus.RUNNING
    assert persisted_scan.findings == []
