from app.db.database import Base

# Import models so SQLAlchemy registers their tables with Base.metadata.
from app.models import Identifier, OTPChallenge, User  # noqa: F401


def test_phase1_models_registered():
    table_names = set(Base.metadata.tables.keys())

    assert "users" in table_names
    assert "identifiers" in table_names
    assert "otp_challenges" in table_names


def test_user_columns():
    columns = Base.metadata.tables["users"].columns

    assert "id" in columns
    assert "email" in columns
    assert "password_hash" in columns
    assert "is_active" in columns
    assert "created_at" in columns


def test_identifier_columns():
    columns = Base.metadata.tables["identifiers"].columns

    assert "id" in columns
    assert "user_id" in columns
    assert "type" in columns
    assert "value_hmac" in columns
    assert "display_value" in columns
    assert "verification_status" in columns
    assert "verified_at" in columns
    assert "created_at" in columns


def test_otp_security_columns():
    columns = Base.metadata.tables["otp_challenges"].columns

    assert "id" in columns
    assert "identifier_id" in columns
    assert "otp_hash" in columns
    assert "expires_at" in columns
    assert "attempts" in columns
    assert "max_attempts" in columns
    assert "used" in columns
    assert "created_at" in columns
