from cryptography.fernet import Fernet
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_JWT_SECRET = "dev-only-jwt-secret-change-in-production"
DEFAULT_OTP_SECRET = "dev-only-otp-hmac-secret-change-in-production"
DEFAULT_IDENTIFIER_SECRET = "dev-only-identifier-hmac-secret"
DEFAULT_IDENTIFIER_ENCRYPTION_KEY = ""


class Settings(BaseSettings):
    app_name: str = "Digital Footprint Exposure Scanner"
    environment: str = "dev"
    expose_dev_otp: bool = False
    jwt_secret: str = DEFAULT_JWT_SECRET
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    login_rate_limit_attempts: int = 5
    login_rate_limit_window_seconds: int = 900
    scan_rate_limit_attempts: int = Field(default=5, ge=1)
    scan_rate_limit_window_seconds: int = Field(default=900, ge=1)
    otp_hmac_secret: str = DEFAULT_OTP_SECRET
    identifier_hmac_secret: str = DEFAULT_IDENTIFIER_SECRET
    identifier_encryption_key: str = DEFAULT_IDENTIFIER_ENCRYPTION_KEY

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_security_configuration(self):
        environment = self.environment.strip().lower()
        if environment in {"prod", "production"}:
            if self.expose_dev_otp:
                raise ValueError(
                    "Development OTP exposure must be disabled in production"
                )
            if not self.identifier_encryption_key:
                raise ValueError(
                    "identifier_encryption_key must be explicitly configured "
                    "in production"
                )
            try:
                Fernet(self.identifier_encryption_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError) as exc:
                raise ValueError(
                    "identifier_encryption_key must be a valid Fernet key"
                ) from exc
            secrets_to_check = {
                "jwt_secret": self.jwt_secret,
                "otp_hmac_secret": self.otp_hmac_secret,
                "identifier_hmac_secret": self.identifier_hmac_secret,
            }
            defaults = {
                "jwt_secret": DEFAULT_JWT_SECRET,
                "otp_hmac_secret": DEFAULT_OTP_SECRET,
                "identifier_hmac_secret": DEFAULT_IDENTIFIER_SECRET,
            }
            for name, secret in secrets_to_check.items():
                if secret == defaults[name] or len(secret) < 32:
                    raise ValueError(
                        f"{name} must be explicitly configured with "
                        "a secret of at least 32 characters in production"
                    )
            if len(set(secrets_to_check.values())) != len(secrets_to_check):
                raise ValueError(
                    "JWT, OTP, and identifier secrets must be different"
                )
        return self


settings = Settings()
