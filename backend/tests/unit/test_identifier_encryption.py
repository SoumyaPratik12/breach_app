import pytest
from cryptography.fernet import Fernet

from app.config.settings import settings
from app.security.identifier_encryption import (
    IDENTIFIER_ENCRYPTION_PREFIX,
    decrypt_identifier,
    encrypt_identifier,
)


@pytest.fixture(autouse=True)
def configure_encryption_key(monkeypatch):
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "identifier_encryption_key", key)


def test_encrypt_then_decrypt_recovers_original_value():
    original = "sammy@example.com"

    encrypted = encrypt_identifier(original)

    assert encrypted.startswith(IDENTIFIER_ENCRYPTION_PREFIX)
    assert decrypt_identifier(encrypted) == original


def test_encryption_produces_different_ciphertext_each_time():
    original = "sammy@example.com"

    first = encrypt_identifier(original)
    second = encrypt_identifier(original)

    assert first != second
    assert decrypt_identifier(first) == original
    assert decrypt_identifier(second) == original


def test_decryption_rejects_tampered_ciphertext():
    encrypted = encrypt_identifier("sammy@example.com")
    tampered = encrypted[:-1] + (
        "A" if encrypted[-1] != "A" else "B"
    )

    with pytest.raises(RuntimeError, match="Unable to decrypt"):
        decrypt_identifier(tampered)


def test_decryption_rejects_unmarked_plaintext():
    with pytest.raises(RuntimeError, match="Unable to decrypt"):
        decrypt_identifier("sammy@example.com")


def test_decryption_rejects_unknown_version():
    with pytest.raises(RuntimeError, match="Unable to decrypt"):
        decrypt_identifier("enc:v2:anything")
