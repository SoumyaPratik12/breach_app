from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.db.database import get_db
from app.models import Identifier, OTPChallenge, User, VerificationStatus
from app.schemas.identifier import (
    IdentifierCreateRequest,
    IdentifierResponse,
    OTPRequestResponse,
    OTPVerifyRequest,
    OTPVerifyResponse,
)
from app.security.auth import get_current_user
from app.services.identifier_service import create_identifier
from app.services.otp_service import create_otp_challenge, verify_otp


router = APIRouter(
    prefix="/identifiers",
    tags=["Identifiers"],
)


@router.post(
    "",
    response_model=IdentifierResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_identifier(
    request: IdentifierCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return create_identifier(
        db=db,
        user_id=current_user.id,
        identifier_type=request.type,
        value=request.value,
    )


@router.get(
    "",
    response_model=list[IdentifierResponse],
)
def list_identifiers(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(Identifier)
        .filter(Identifier.user_id == current_user.id)
        .order_by(Identifier.created_at)
        .all()
    )


@router.post(
    "/{identifier_id}/otp",
    response_model=OTPRequestResponse,
)
def request_identifier_otp(
    identifier_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    identifier = (
        db.query(Identifier)
        .filter(
            Identifier.id == identifier_id,
            Identifier.user_id == current_user.id,
        )
        .first()
    )
    if identifier is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identifier not found",
        )

    # Do not generate a code that cannot be delivered safely.
    if not (
        settings.environment == "dev"
        and settings.expose_dev_otp
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OTP delivery is not configured",
        )

    challenge: OTPChallenge
    challenge, otp = create_otp_challenge(db, identifier)
    expires_at: datetime = challenge.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    return OTPRequestResponse(
        message="OTP generated for development verification",
        expires_at=expires_at,
        dev_otp=otp,
    )


@router.post(
    "/{identifier_id}/verify",
    response_model=OTPVerifyResponse,
)
def verify_identifier_otp(
    identifier_id: str,
    request: OTPVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    identifier = (
        db.query(Identifier)
        .filter(
            Identifier.id == identifier_id,
            Identifier.user_id == current_user.id,
        )
        .first()
    )
    if identifier is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identifier not found",
        )

    verify_otp(db, identifier, request.otp)

    return OTPVerifyResponse(
        message="Identifier verified successfully",
        verification_status=VerificationStatus.VERIFIED,
    )
