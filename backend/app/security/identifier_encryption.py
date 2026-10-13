from cryptography.fernet import Fernet, InvalidToken

from app.config.settings import settings


IDENTIFIER_ENCRYPTION_PREFIX = "enc:v1:"


def _get_fernet() -> Fernet:
    key = settings.identifier_encryption_key
    if not key:
        raise RuntimeError(
            "Identifier encryption key is not configured"
        )
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError(
            "Identifier encryption key is invalid"
        ) from exc


def encrypt_identifier(value: str) -> str:
    """Encrypt an identifier value for database storage."""
    token = _get_fernet().encrypt(value.encode("utf-8")).decode("ascii")
    return f"{IDENTIFIER_ENCRYPTION_PREFIX}{token}"


def decrypt_identifier(value: str) -> str:
    """Decrypt an identifier value from database storage."""
    if not value.startswith(IDENTIFIER_ENCRYPTION_PREFIX):
        raise RuntimeError("Unable to decrypt stored identifier")

    try:
        token = value[len(IDENTIFIER_ENCRYPTION_PREFIX):]
        plaintext = _get_fernet().decrypt(token.encode("ascii"))
    except (InvalidToken, ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError(
            "Unable to decrypt stored identifier"
        ) from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(
            "Unable to decrypt stored identifier"
        ) from exc
