import hashlib
import hmac
import secrets

from app.config.settings import settings


def hash_otp(otp: str) -> str:
    """Return a keyed hash of an OTP using a server-side secret."""
    return hmac.new(
        settings.otp_hmac_secret.encode("utf-8"),
        otp.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_identifier_hmac(
    value: str,
    secret: str,
) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_otp() -> str:
    """Generate a uniformly selected six-digit OTP, including leading zeros."""
    return f"{secrets.randbelow(1_000_000):06d}"
