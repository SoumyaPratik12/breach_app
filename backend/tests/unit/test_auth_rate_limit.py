import pytest

from app.api.auth import login_rate_limiter
from app.config.settings import settings


@pytest.fixture(autouse=True)
def reset_login_rate_limiter():
    login_rate_limiter.reset()
    yield
    login_rate_limiter.reset()


def test_login_returns_generic_401_for_invalid_credentials(client):
    response = client.post(
        "/auth/login",
        json={
            "email": "unknown@example.com",
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_login_returns_429_after_failed_attempt_threshold(client):
    for _ in range(settings.login_rate_limit_attempts):
        response = client.post(
            "/auth/login",
            json={
                "email": "unknown@example.com",
                "password": "WrongPassword123!",
            },
        )
        assert response.status_code == 401

    response = client.post(
        "/auth/login",
        json={
            "email": "unknown@example.com",
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code == 429
    assert response.json()["detail"] == (
        "Too many failed login attempts. Please try again later."
    )
    assert response.headers["retry-after"] == str(
        settings.login_rate_limit_window_seconds
    )


def test_login_succeeds_for_valid_credentials(client):
    registration = client.post(
        "/auth/register",
        json={
            "email": "login-test@example.com",
            "password": "TestPassword123!",
        },
    )
    assert registration.status_code == 201

    response = client.post(
        "/auth/login",
        json={
            "email": "login-test@example.com",
            "password": "TestPassword123!",
        },
    )

    assert response.status_code == 200
    assert response.json()["access_token"]
    assert response.json()["token_type"] == "bearer"
