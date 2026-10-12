from app.config.settings import settings
from app.security.crypto import (
    generate_identifier_hmac,
    generate_otp,
    hash_otp,
)


def test_otp_hash_depends_on_secret(monkeypatch):
    monkeypatch.setattr(settings, "otp_hmac_secret", "secret-one")
    first = hash_otp("123456")

    monkeypatch.setattr(settings, "otp_hmac_secret", "secret-two")
    second = hash_otp("123456")

    assert first != second


def test_same_otp_and_secret_produce_same_hash(monkeypatch):
    monkeypatch.setattr(settings, "otp_hmac_secret", "test-secret")

    assert hash_otp("123456") == hash_otp("123456")


def test_generated_otp_is_six_digits():
    for _ in range(100):
        otp = generate_otp()
        assert len(otp) == 6
        assert otp.isdigit()


def test_identifier_hmac_is_deterministic():
    first = generate_identifier_hmac("user@example.com", "test-secret")
    second = generate_identifier_hmac("user@example.com", "test-secret")

    assert first == second
