import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import Text

from app.db.migrate_identifier_encryption import (
    MigrationError,
    _create_verified_backup,
    migrate_database,
)
from app.db.database import Base
from app.models import Identifier
from app.security.identifier_encryption import IDENTIFIER_ENCRYPTION_PREFIX


@pytest.fixture
def encryption_key():
    return Fernet.generate_key().decode("ascii")


@pytest.fixture
def migration_database(tmp_path: Path) -> Path:
    database_path = tmp_path / "identifiers.sqlite"
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute(
            """
            CREATE TABLE identifiers (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                type TEXT NOT NULL,
                value_hmac TEXT NOT NULL,
                display_value TEXT NOT NULL,
                verification_status TEXT NOT NULL,
                verified_at TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO identifiers VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "identifier-1",
                "user-1",
                "email",
                "hmac-value",
                "sammy@example.com",
                "verified",
                "2026-10-01T12:30:00+00:00",
                "2026-09-30T09:15:00+00:00",
            ),
        )
        connection.commit()
    return database_path


def _read_identifier(database_path: Path) -> tuple[object, ...]:
    with closing(sqlite3.connect(database_path)) as connection:
        return connection.execute(
            """
            SELECT id, user_id, type, value_hmac, display_value,
                   verification_status, verified_at, created_at
            FROM identifiers
            """
        ).fetchone()


def _read_identifiers(database_path: Path) -> list[tuple[object, ...]]:
    with closing(sqlite3.connect(database_path)) as connection:
        return connection.execute(
            """
            SELECT id, user_id, type, value_hmac, display_value,
                   verification_status, verified_at, created_at
            FROM identifiers
            ORDER BY id
            """
        ).fetchall()


def test_migration_encrypts_values_and_preserves_other_fields(
    migration_database: Path,
    encryption_key: str,
):
    original = _read_identifier(migration_database)

    encrypted_count, already_encrypted_count, backup_path = migrate_database(
        migration_database,
        encryption_key,
    )

    migrated = _read_identifier(migration_database)
    assert encrypted_count == 1
    assert already_encrypted_count == 0
    assert backup_path.is_file()
    assert backup_path.parent == migration_database.parent
    assert migrated[:4] == original[:4]
    assert migrated[4] != original[4]
    assert migrated[5:] == original[5:]
    assert Fernet(encryption_key.encode("ascii")).decrypt(
        migrated[4][len(IDENTIFIER_ENCRYPTION_PREFIX):].encode("ascii")
    ).decode("utf-8") == original[4]
    assert _read_identifier(backup_path) == original


def test_migration_is_safe_to_rerun(
    migration_database: Path,
    encryption_key: str,
):
    migrate_database(migration_database, encryption_key)
    encrypted_record = _read_identifier(migration_database)

    encrypted_count, already_encrypted_count, _ = migrate_database(
        migration_database,
        encryption_key,
    )

    assert encrypted_count == 0
    assert already_encrypted_count == 1
    assert _read_identifier(migration_database) == encrypted_record


def test_invalid_key_fails_before_backup_or_database_changes(
    migration_database: Path,
):
    original = _read_identifier(migration_database)

    with pytest.raises(MigrationError, match="valid identifier encryption key"):
        migrate_database(migration_database, "invalid-key")

    assert _read_identifier(migration_database) == original
    assert list(migration_database.parent.glob("*.bak")) == []


def test_wrong_key_for_marked_value_rolls_back_all_updates(
    migration_database: Path,
    encryption_key: str,
):
    other_key = Fernet.generate_key()
    with closing(sqlite3.connect(migration_database)) as connection:
        connection.execute(
            "UPDATE identifiers SET display_value = ? WHERE id = ?",
            (
                f"{IDENTIFIER_ENCRYPTION_PREFIX}"
                f"{Fernet(other_key).encrypt(b'sammy@example.com').decode()}",
                "identifier-1",
            ),
        )
        connection.commit()
    original_records = _read_identifiers(migration_database)

    with pytest.raises(MigrationError, match="cannot be verified"):
        migrate_database(migration_database, encryption_key)

    assert _read_identifiers(migration_database) == original_records


@pytest.mark.parametrize(
    "invalid_utf8",
    [False, True],
)
def test_malformed_marked_value_fails_closed(
    migration_database: Path,
    encryption_key: str,
    invalid_utf8: bool,
):
    if invalid_utf8:
        token = Fernet(encryption_key.encode()).encrypt(bytes([0xFF])).decode()
    else:
        token = "not-a-token"
    marked_value = f"{IDENTIFIER_ENCRYPTION_PREFIX}{token}"
    with closing(sqlite3.connect(migration_database)) as connection:
        connection.execute(
            "UPDATE identifiers SET display_value = ?",
            (marked_value,),
        )
        connection.commit()
    original = _read_identifier(migration_database)

    with pytest.raises(MigrationError, match="cannot be verified"):
        migrate_database(migration_database, encryption_key)

    assert _read_identifier(migration_database) == original


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "enc:v2:some-token",
        "gAAAAABlY2lwaGVydGV4dA==",
    ],
)
def test_unsupported_ciphertext_without_marker_fails_closed(
    migration_database: Path,
    encryption_key: str,
    unsafe_value: str,
):
    with closing(sqlite3.connect(migration_database)) as connection:
        connection.execute(
            "UPDATE identifiers SET display_value = ?",
            (unsafe_value,),
        )
        connection.commit()
    original = _read_identifier(migration_database)

    with pytest.raises(MigrationError, match="unsupported encryption format"):
        migrate_database(migration_database, encryption_key)

    assert _read_identifier(migration_database) == original


def test_backup_verification_rejects_record_mismatch(
    migration_database: Path,
):
    with pytest.raises(MigrationError, match="does not match"):
        _create_verified_backup(migration_database, [])

    assert list(migration_database.parent.glob("*.bak")) == []


def test_invalid_schema_fails_without_creating_backup(
    tmp_path: Path,
    encryption_key: str,
):
    database_path = tmp_path / "wrong-schema.sqlite"
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("CREATE TABLE unrelated (id TEXT)")
        connection.commit()

    with pytest.raises(MigrationError, match="identifiers table"):
        migrate_database(database_path, encryption_key)

    assert list(tmp_path.glob("*.bak")) == []


def test_display_value_uses_unbounded_text_storage():
    column = Base.metadata.tables["identifiers"].columns["display_value"]

    assert isinstance(column.type, Text)
