import pytest

from app.api.password_exposure import password_check_rate_limiter
from app.config.settings import settings


@pytest.fixture(autouse=True)
def reset_password_check_rate_limiter():
    password_check_rate_limiter.reset()
    yield
    password_check_rate_limiter.reset()


def test_register_login_verify_scan_and_password_check(
    client,
    monkeypatch,
):
    from app.api import password_exposure as password_exposure_api

    monkeypatch.setattr(settings, "environment", "dev")
    monkeypatch.setattr(settings, "expose_dev_otp", True)

    credentials = {
        "email": "security-workflow@example.com",
        "password": "TestPassword123!",
    }
    registration = client.post("/auth/register", json=credentials)
    assert registration.status_code == 201, registration.text

    login = client.post("/auth/login", json=credentials)
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    identifier_response = client.post(
        "/identifiers",
        headers=headers,
        json={"type": "email", "value": credentials["email"]},
    )
    assert identifier_response.status_code == 201, identifier_response.text
    identifier_id = identifier_response.json()["id"]

    blocked_scan = client.post(
        f"/identifiers/{identifier_id}/scans",
        headers=headers,
    )
    assert blocked_scan.status_code == 409

    otp_response = client.post(
        f"/identifiers/{identifier_id}/otp",
        headers=headers,
    )
    assert otp_response.status_code == 200, otp_response.text

    verification = client.post(
        f"/identifiers/{identifier_id}/verify",
        headers=headers,
        json={"otp": otp_response.json()["dev_otp"]},
    )
    assert verification.status_code == 200, verification.text
    assert verification.json()["verification_status"] == "verified"

    scan = client.post(
        f"/identifiers/{identifier_id}/scans",
        headers=headers,
    )
    assert scan.status_code == 201, scan.text
    assert scan.json()["status"] == "completed"
    assert scan.json()["is_simulated"] is True
    assert all(
        finding["simulated"] is True and finding["verified"] is False
        for finding in scan.json()["findings"]
    )

    monkeypatch.setattr(
        password_exposure_api,
        "check_password_exposure",
        lambda _password: 3,
    )
    password = "Candidate-Password-123!"
    password_check = client.post(
        "/password-exposure/check",
        headers=headers,
        json={"password": password},
    )
    assert password_check.status_code == 200, password_check.text
    assert password_check.json()["exposed"] is True
    assert password_check.json()["occurrence_count"] == 3
    assert password not in password_check.text