from datetime import datetime, timedelta, timezone

from app.config.settings import settings
from app.models import OTPChallenge


def register_and_authenticate(client, email):
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "TestPassword123!",
        },
    )
    assert response.status_code == 201, response.text

    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def create_email_identifier(client, headers, email):
    response = client.post(
        "/identifiers",
        headers=headers,
        json={"type": "email", "value": email},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def request_otp(client, headers, identifier_id):
    response = client.post(
        f"/identifiers/{identifier_id}/otp",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()["dev_otp"]


def enable_test_otp(monkeypatch):
    monkeypatch.setattr(settings, "environment", "dev")
    monkeypatch.setattr(settings, "expose_dev_otp", True)


def test_valid_otp_verifies_identifier_and_cannot_be_reused(
    client, monkeypatch
):
    enable_test_otp(monkeypatch)
    headers = register_and_authenticate(client, "otp-success@example.com")
    identifier_id = create_email_identifier(
        client, headers, "otp-success@example.com"
    )

    otp = request_otp(client, headers, identifier_id)

    response = client.post(
        f"/identifiers/{identifier_id}/verify",
        headers=headers,
        json={"otp": otp},
    )
    assert response.status_code == 200, response.text
    assert response.json()["verification_status"] == "verified"

    reuse_response = client.post(
        f"/identifiers/{identifier_id}/verify",
        headers=headers,
        json={"otp": otp},
    )
    assert reuse_response.status_code == 400


def test_three_invalid_attempts_invalidate_challenge(
    client, db_session, monkeypatch
):
    enable_test_otp(monkeypatch)
    headers = register_and_authenticate(client, "otp-attempts@example.com")
    identifier_id = create_email_identifier(
        client, headers, "otp-attempts@example.com"
    )
    request_otp(client, headers, identifier_id)

    for _ in range(3):
        response = client.post(
            f"/identifiers/{identifier_id}/verify",
            headers=headers,
            json={"otp": "000000"},
        )
        assert response.status_code == 400

    challenge = (
        db_session.query(OTPChallenge)
        .filter(OTPChallenge.identifier_id == identifier_id)
        .first()
    )
    assert challenge is not None
    assert challenge.attempts == 3
    assert challenge.used is True

    # The next request must not accept another guess against the
    # invalidated challenge.
    response = client.post(
        f"/identifiers/{identifier_id}/verify",
        headers=headers,
        json={"otp": "000000"},
    )
    assert response.status_code == 400
    assert "No active OTP challenge" in response.json()["detail"]


def test_expired_otp_is_rejected(client, db_session, monkeypatch):
    enable_test_otp(monkeypatch)
    headers = register_and_authenticate(client, "otp-expired@example.com")
    identifier_id = create_email_identifier(
        client, headers, "otp-expired@example.com"
    )
    request_otp(client, headers, identifier_id)

    challenge = (
        db_session.query(OTPChallenge)
        .filter(OTPChallenge.identifier_id == identifier_id)
        .first()
    )
    assert challenge is not None

    challenge.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()

    response = client.post(
        f"/identifiers/{identifier_id}/verify",
        headers=headers,
        json={"otp": "123456"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "OTP has expired"


def test_user_cannot_verify_another_users_identifier(
    client, monkeypatch
):
    enable_test_otp(monkeypatch)

    owner_headers = register_and_authenticate(
        client, "otp-owner@example.com"
    )
    identifier_id = create_email_identifier(
        client, owner_headers, "otp-owner@example.com"
    )

    other_headers = register_and_authenticate(
        client, "otp-other@example.com"
    )
    response = client.post(
        f"/identifiers/{identifier_id}/verify",
        headers=other_headers,
        json={"otp": "123456"},
    )

    assert response.status_code == 404


def test_otp_request_cooldown(client, monkeypatch):
    enable_test_otp(monkeypatch)
    headers = register_and_authenticate(client, "otp-cooldown@example.com")
    identifier_id = create_email_identifier(
        client, headers, "otp-cooldown@example.com"
    )

    request_otp(client, headers, identifier_id)

    response = client.post(
        f"/identifiers/{identifier_id}/otp",
        headers=headers,
    )
    assert response.status_code == 429


def test_new_otp_challenge_invalidates_previous_challenge(
    client, db_session, monkeypatch
):
    enable_test_otp(monkeypatch)
    headers = register_and_authenticate(
        client, "otp-replacement@example.com"
    )
    identifier_id = create_email_identifier(
        client, headers, "otp-replacement@example.com"
    )
    old_otp = request_otp(client, headers, identifier_id)
    # Bypass the 60-second cooldown for this controlled test.
    challenge = (
        db_session.query(OTPChallenge)
        .filter(OTPChallenge.identifier_id == identifier_id)
        .first()
    )
    assert challenge is not None
    challenge.created_at = datetime.now(timezone.utc) - timedelta(
        seconds=61
    )
    db_session.commit()
    new_otp = request_otp(client, headers, identifier_id)
    assert new_otp != old_otp
    # The old OTP must no longer verify the identifier.
    old_otp_response = client.post(
        f"/identifiers/{identifier_id}/verify",
        headers=headers,
        json={"otp": old_otp},
    )
    assert old_otp_response.status_code == 400
