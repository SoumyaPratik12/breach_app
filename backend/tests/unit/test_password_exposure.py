import hashlib

import httpx
import pytest

from app.services.password_exposure import (
    PasswordExposureProviderError,
    check_password_exposure,
)


class MockResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "provider error",
                request=httpx.Request("GET", "https://example.test"),
                response=httpx.Response(self.status_code),
            )


def test_match_returns_occurrence_count(monkeypatch):
    password = "example-password"
    digest = hashlib.sha1(
        password.encode(),
        usedforsecurity=False,
    ).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    captured = {}

    def fake_get(url, headers, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["timeout"] = timeout
        return MockResponse(f"{suffix}:42\n")

    monkeypatch.setattr(
        "app.services.password_exposure.httpx.get",
        fake_get,
    )

    assert check_password_exposure(password) == 42
    assert captured["url"].endswith(prefix)
    assert password not in captured["url"]
    assert digest not in captured["url"]
    assert captured["headers"]["Add-Padding"] == "true"
    assert captured["timeout"] > 0


def test_no_match_returns_zero(monkeypatch):
    monkeypatch.setattr(
        "app.services.password_exposure.httpx.get",
        lambda *args, **kwargs: MockResponse("AAAAAAAAAAAAAAAAAAAA:3\n"),
    )

    assert check_password_exposure("a different password") == 0


def test_provider_http_error_is_sanitized(monkeypatch):
    def fake_get(*args, **kwargs):
        return MockResponse("private diagnostic", status_code=503)

    monkeypatch.setattr(
        "app.services.password_exposure.httpx.get",
        fake_get,
    )

    with pytest.raises(PasswordExposureProviderError) as exc:
        check_password_exposure("example-password")

    assert "private diagnostic" not in str(exc.value)


def test_network_error_is_sanitized(monkeypatch):
    def fake_get(*args, **kwargs):
        raise httpx.TimeoutException("sensitive diagnostic")

    monkeypatch.setattr(
        "app.services.password_exposure.httpx.get",
        fake_get,
    )

    with pytest.raises(PasswordExposureProviderError) as exc:
        check_password_exposure("example-password")

    assert "sensitive diagnostic" not in str(exc.value)


def test_malformed_provider_response_fails_closed(monkeypatch):
    monkeypatch.setattr(
        "app.services.password_exposure.httpx.get",
        lambda *args, **kwargs: MockResponse("not-a-valid-entry"),
    )

    with pytest.raises(PasswordExposureProviderError):
        check_password_exposure("example-password")