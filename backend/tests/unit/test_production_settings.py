import pytest
from pydantic import ValidationError

from app.config.settings import Settings


def test_production_rejects_default_secrets():
    with pytest.raises(ValidationError):
        Settings(environment="production")


def test_production_rejects_dev_otp_exposure():
    with pytest.raises(ValidationError):
        Settings(
            environment="production",
            expose_dev_otp=True,
            jwt_secret="j" * 40,
            otp_hmac_secret="o" * 40,
            identifier_hmac_secret="i" * 40,
        )


def test_production_accepts_distinct_configured_secrets():
    configured = Settings(
        environment="production",
        jwt_secret="j" * 40,
        otp_hmac_secret="o" * 40,
        identifier_hmac_secret="i" * 40,
    )
    assert configured.environment == "production"
    assert configured.expose_dev_otp is False
