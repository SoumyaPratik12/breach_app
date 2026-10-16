import pytest

from app.api.password_exposure import password_check_rate_limiter
from app.config.settings import settings
from app.services.password_exposure import PasswordExposureProviderError


@pytest.fixture(autouse=True)
def reset_password_check_rate_limiter():
    password_check_rate_limiter.reset()
    yield
    password_check_rate_limiter.reset()


def register_and_authenticate(client, email="password-check@example.com"):
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


def test_password_check_requires_authentication(client):
    response = client.post(
        "/password-exposure/check",
        json={"password": "Example-Password-123!"},
    )

    assert response.status_code == 401


def test_password_check_returns_exposure_result_without_password(
    client,
    monkeypatch,
):
    from app.api import password_exposure as api

    password = "Example-Password-123!"
    captured = {}

    def fake_check_password_exposure(value):
        captured["password"] = value
        return 42

    monkeypatch.setattr(
        api,
        "check_password_exposure",
        fake_check_password_exposure,
    )

    headers = register_and_authenticate(client)
    response = client.post(
        "/password-exposure/check",
        headers=headers,
        json={"password": password},
    )

    assert response.status_code == 200, response.text
    assert response.json()["exposed"] is True
    assert response.json()["occurrence_count"] == 42
    assert response.json()["source"] == (
        "Have I Been Pwned Pwned Passwords"
    )
    assert password not in response.text
    assert captured["password"] == password


def test_password_check_provider_failure_is_sanitized(
    client,
    monkeypatch,
):
    from app.api import password_exposure as api

    def fake_check_password_exposure(_password):
        raise PasswordExposureProviderError(
            "private provider diagnostic"
        )

    monkeypatch.setattr(
        api,
        "check_password_exposure",
        fake_check_password_exposure,
    )

    headers = register_and_authenticate(client)
    response = client.post(
        "/password-exposure/check",
        headers=headers,
        json={"password": "Example-Password-123!"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "Password exposure service is temporarily unavailable"
    )
    assert "private provider diagnostic" not in response.text


def test_password_check_rate_limit_returns_429(
    client,
    monkeypatch,
):
    from app.api import password_exposure as api

    monkeypatch.setattr(
        api,
        "check_password_exposure",
        lambda _password: 0,
    )

    headers = register_and_authenticate(client)

    for _ in range(settings.scan_rate_limit_attempts):
        response = client.post(
            "/password-exposure/check",
            headers=headers,
            json={"password": "Example-Password-123!"},
        )
        assert response.status_code == 200, response.text

    response = client.post(
        "/password-exposure/check",
        headers=headers,
        json={"password": "Example-Password-123!"},
    )

    assert response.status_code == 429
    assert response.json()["detail"] == (
        "Password check rate limit exceeded. Please try again later."
    )
    assert response.headers["retry-after"] == str(
        settings.scan_rate_limit_window_seconds
    )