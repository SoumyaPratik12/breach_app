import argparse
import base64
import binascii
import os
import re
import sqlite3
import sys
from collections.abc import Sequence
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from app.config.settings import settings
from app.security.identifier_encryption import IDENTIFIER_ENCRYPTION_PREFIX


class MigrationError(Exception):
    pass


def _validated_fernet(key: str) -> Fernet:
    try:
        return Fernet(key.encode("ascii"))
    except (AttributeError, UnicodeEncodeError, ValueError) as exc:
        raise MigrationError(
            "A valid identifier encryption key must be configured."
        ) from exc


def _validated_database_path(database_path: Path) -> Path:
    try:
        path = database_path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise MigrationError(
            "The specified SQLite database file does not exist."
        ) from exc
    if not path.is_file():
        raise MigrationError(
            "The specified SQLite database path is not a file."
        )
    return path


def _validate_identifier_table(connection: sqlite3.Connection) -> None:
    row = connection.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name = 'identifiers'"
    ).fetchone()
    if row is None:
        raise MigrationError(
            "The SQLite database does not contain an identifiers table."
        )

    columns = {
        column[1]
        for column in connection.execute("PRAGMA table_info(identifiers)")
    }
    if not {"id", "display_value"}.issubset(columns):
        raise MigrationError(
            "The identifiers table is missing required columns."
        )


def _identifier_snapshot(
    connection: sqlite3.Connection,
) -> list[tuple[object, ...]]:
    return connection.execute(
        "SELECT * FROM identifiers ORDER BY id"
    ).fetchall()


def _looks_like_fernet_token(value: str) -> bool:
    if re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value) is None:
        return False
    if value.startswith("gAAAA"):
        return True
    try:
        token = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(token) >= 57 and token[0] == 0x80


def _create_verified_backup(
    database_path: Path,
    expected_records: list[tuple[object, ...]],
) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = database_path.with_name(
        f"{database_path.name}.{timestamp}.bak"
    )
    try:
        backup_fd = os.open(
            backup_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError as exc:
        raise MigrationError(
            "The timestamped backup already exists; refusing to overwrite it."
        ) from exc
    except OSError as exc:
        raise MigrationError(
            "Unable to create a backup next to the SQLite database."
        ) from exc
    os.close(backup_fd)

    try:
        with closing(sqlite3.connect(database_path)) as source:
            with closing(sqlite3.connect(backup_path)) as destination:
                source.backup(destination)

        with closing(sqlite3.connect(backup_path)) as verification:
            integrity = verification.execute(
                "PRAGMA integrity_check"
            ).fetchone()
            if integrity != ("ok",):
                raise MigrationError(
                    "The database backup failed its integrity check."
                )
            _validate_identifier_table(verification)
            if _identifier_snapshot(verification) != expected_records:
                raise MigrationError(
                    "The backup does not match the locked source records."
                )
    except (OSError, sqlite3.Error, MigrationError) as exc:
        try:
            backup_path.unlink(missing_ok=True)
        except OSError as cleanup_error:
            raise MigrationError(
                "The backup could not be verified and its incomplete file "
                "could not be removed."
            ) from cleanup_error
        if isinstance(exc, MigrationError):
            raise
        raise MigrationError(
            "Unable to create and verify the SQLite database backup."
        ) from exc

    return backup_path


def _encrypt_records(
    database_path: Path,
    fernet: Fernet,
) -> tuple[int, int, Path]:
    connection = sqlite3.connect(database_path, timeout=30)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _validate_identifier_table(connection)
        expected_records = _identifier_snapshot(connection)
        backup_path = _create_verified_backup(
            database_path,
            expected_records,
        )
        records = connection.execute(
            "SELECT id, display_value FROM identifiers"
        ).fetchall()

        updates: list[tuple[str, str]] = []
        already_encrypted_count = 0
        for identifier_id, display_value in records:
            if not isinstance(identifier_id, str) or not isinstance(
                display_value, str
            ):
                raise MigrationError(
                    "An identifier record has an invalid value; "
                    "no records were changed."
                )

            if display_value.startswith(IDENTIFIER_ENCRYPTION_PREFIX):
                token = display_value[
                    len(IDENTIFIER_ENCRYPTION_PREFIX):
                ]
                try:
                    plaintext = fernet.decrypt(token.encode("ascii"))
                    plaintext.decode("utf-8")
                except (
                    InvalidToken,
                    UnicodeEncodeError,
                    UnicodeDecodeError,
                ) as exc:
                    raise MigrationError(
                        "A marked identifier cannot be verified with the "
                        "configured key; "
                        "no records were changed."
                    ) from exc
                already_encrypted_count += 1
            elif display_value.startswith("enc:") or _looks_like_fernet_token(
                display_value
            ):
                raise MigrationError(
                    "An identifier has an unsupported encryption format; "
                    "no records were changed."
                )
            else:
                ciphertext = fernet.encrypt(
                    display_value.encode("utf-8")
                ).decode("ascii")
                updates.append(
                    (
                        f"{IDENTIFIER_ENCRYPTION_PREFIX}{ciphertext}",
                        identifier_id,
                    )
                )

        connection.executemany(
            "UPDATE identifiers SET display_value = ? WHERE id = ?",
            updates,
        )
        connection.commit()
        encrypted_count = len(updates)
    except (sqlite3.Error, MigrationError):
        connection.rollback()
        raise
    finally:
        connection.close()

    return encrypted_count, already_encrypted_count, backup_path


def migrate_database(database_path: Path, key: str) -> tuple[int, int, Path]:
    fernet = _validated_fernet(key)
    resolved_path = _validated_database_path(database_path)
    return _encrypt_records(resolved_path, fernet)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Encrypt plaintext identifiers in an SQLite database. "
            "A verified timestamped backup is created first."
        )
    )
    parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="path to the SQLite database to migrate",
    )
    arguments = parser.parse_args(argv)

    try:
        encrypted, already_encrypted, backup_path = migrate_database(
            arguments.database,
            settings.identifier_encryption_key,
        )
    except (MigrationError, sqlite3.Error) as exc:
        print(f"Migration failed: {exc}", file=sys.stderr)
        return 1

    print("Identifier encryption migration completed.")
    print(f"Encrypted records: {encrypted}")
    print(f"Already-encrypted records: {already_encrypted}")
    print(f"Verified backup: {backup_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
