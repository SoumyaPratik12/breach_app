from cryptography.fernet import Fernet
import pytest
from pydantic import ValidationError

from app.config.settings import Settings


def _configured_secrets():
    return {
        "jwt_secret": "j" * 40,
        "otp_hmac_secret": "o" * 40,
        "identifier_hmac_secret": "i" * 40,
    }


def test_production_rejects_default_secrets():
    with pytest.raises(ValidationError):
        Settings(environment="production")


def test_production_requires_identifier_encryption_key():
    with pytest.raises(
        ValidationError,
        match="identifier_encryption_key must be explicitly configured",
    ):
        Settings(
            environment="production",
            identifier_encryption_key="",
            **_configured_secrets(),
        )


@pytest.mark.parametrize("key", ["not-a-fernet-key", "é"])
def test_production_rejects_invalid_identifier_encryption_key(key):
    with pytest.raises(
        ValidationError,
        match="identifier_encryption_key must be a valid Fernet key",
    ):
        Settings(
            environment="production",
            identifier_encryption_key=key,
            **_configured_secrets(),
        )


def test_production_rejects_dev_otp_exposure():
    with pytest.raises(ValidationError):
        Settings(
            environment="production",
            expose_dev_otp=True,
            identifier_encryption_key=Fernet.generate_key().decode("ascii"),
            **_configured_secrets(),
        )


def test_production_accepts_distinct_configured_secrets():
    configured = Settings(
        environment="production",
        identifier_encryption_key=Fernet.generate_key().decode("ascii"),
        **_configured_secrets(),
    )
    assert configured.environment == "production"
    assert configured.expose_dev_otp is False


@pytest.mark.parametrize("algorithm", ["HS384", "HS512", "none", "invalid"])
def test_rejects_unsupported_jwt_algorithm(algorithm):
    with pytest.raises(ValueError, match="jwt_algorithm must be HS256"):
        Settings(jwt_algorithm=algorithm)


def test_accepts_hs256_jwt_algorithm():
    settings = Settings(jwt_algorithm="HS256")
    assert settings.jwt_algorithm == "HS256"
