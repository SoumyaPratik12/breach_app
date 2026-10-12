from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import Identifier, OTPChallenge, VerificationStatus
from app.security.crypto import generate_otp, hash_otp


OTP_EXPIRY_MINUTES = 10
MAX_OTP_ATTEMPTS = 3


def create_otp_challenge(
    db: Session,
    identifier: Identifier,
) -> tuple[OTPChallenge, str]:
    if identifier.verification_status == VerificationStatus.VERIFIED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Identifier is already verified",
        )

    now = datetime.now(timezone.utc)
    latest_challenge = (
        db.query(OTPChallenge)
        .filter(OTPChallenge.identifier_id == identifier.id)
        .order_by(OTPChallenge.created_at.desc())
        .first()
    )
    if latest_challenge is not None:
        latest_created = latest_challenge.created_at
        if latest_created.tzinfo is None:
            latest_created = latest_created.replace(tzinfo=timezone.utc)
        if latest_created > now - timedelta(seconds=60):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Please wait before requesting another OTP",
            )

    # Invalidate any previous unused challenges.
    previous_challenges = (
        db.query(OTPChallenge)
        .filter(
            OTPChallenge.identifier_id == identifier.id,
            OTPChallenge.used.is_(False),
        )
        .all()
    )

    for challenge in previous_challenges:
        challenge.used = True

    otp = generate_otp()

    challenge = OTPChallenge(
        identifier_id=identifier.id,
        otp_hash=hash_otp(otp),
        expires_at=datetime.now(timezone.utc)
        + timedelta(minutes=OTP_EXPIRY_MINUTES),
        max_attempts=MAX_OTP_ATTEMPTS,
    )

    db.add(challenge)
    db.commit()
    db.refresh(challenge)

    return challenge, otp


def verify_otp(
    db: Session,
    identifier: Identifier,
    otp: str,
) -> OTPChallenge:
    now = datetime.now(timezone.utc)

    challenge = (
        db.query(OTPChallenge)
        .filter(
            OTPChallenge.identifier_id == identifier.id,
            OTPChallenge.used.is_(False),
        )
        .order_by(OTPChallenge.created_at.desc())
        .first()
    )

    if challenge is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active OTP challenge",
        )

    expires_at = challenge.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        challenge.used = True
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired",
        )

    if challenge.attempts >= challenge.max_attempts:
        challenge.used = True
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Maximum OTP attempts exceeded",
        )

    challenge.attempts += 1

    if hash_otp(otp) != challenge.otp_hash:
        if challenge.attempts >= challenge.max_attempts:
            challenge.used = True

        db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP",
        )

    challenge.used = True

    identifier.verification_status = VerificationStatus.VERIFIED
    identifier.verified_at = now

    db.commit()
    db.refresh(challenge)

    return challenge
