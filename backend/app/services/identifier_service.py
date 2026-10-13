import re

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.models import Identifier, IdentifierType, VerificationStatus
from app.security.crypto import generate_identifier_hmac
from app.security.identifier_encryption import encrypt_identifier


def normalize_identifier(
    identifier_type: IdentifierType,
    value: str,
) -> str:
    value = value.strip()

    if identifier_type == IdentifierType.EMAIL:
        return value.lower()

    if identifier_type == IdentifierType.PHONE:
        # Keep digits and an optional leading +.
        normalized = re.sub(r"[^\d+]", "", value)

        if normalized.startswith("+"):
            return "+" + re.sub(r"\D", "", normalized[1:])

        return re.sub(r"\D", "", normalized)

    if identifier_type in {
        IdentifierType.USERNAME,
        IdentifierType.NAME,
    }:
        return " ".join(value.split()).lower()

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Unsupported identifier type",
    )


def create_identifier(
    db: Session,
    user_id: str,
    identifier_type: IdentifierType,
    value: str,
) -> Identifier:
    normalized = normalize_identifier(
        identifier_type,
        value,
    )

    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Identifier value cannot be empty",
        )

    value_hmac = generate_identifier_hmac(
        normalized,
        settings.identifier_hmac_secret,
    )

    existing = (
        db.query(Identifier)
        .filter(
            Identifier.user_id == user_id,
            Identifier.type == identifier_type,
            Identifier.value_hmac == value_hmac,
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Identifier already exists",
        )

    identifier = Identifier(
        user_id=user_id,
        type=identifier_type,
        value_hmac=value_hmac,
        display_value=encrypt_identifier(value.strip()),
        verification_status=VerificationStatus.PENDING,
    )

    db.add(identifier)
    db.commit()
    db.refresh(identifier)

    return identifier
