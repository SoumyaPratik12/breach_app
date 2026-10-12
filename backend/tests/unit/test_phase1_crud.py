from datetime import datetime, timedelta, timezone

from app.models import (
    Identifier,
    IdentifierType,
    OTPChallenge,
    User,
    VerificationStatus,
)
from app.security.crypto import (
    generate_identifier_hmac,
    generate_otp,
    hash_otp,
)
from app.security.passwords import hash_password, verify_password
from app.config.settings import settings


def test_phase1_crud_flow(db_session):
    db = db_session

    user = User(
        email="phase1-test@example.com",
        password_hash=hash_password("TestPassword123!"),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    assert user.id is not None
    assert verify_password("TestPassword123!", user.password_hash)

    email = "phase1-test@example.com"

    identifier = Identifier(
        user_id=user.id,
        type=IdentifierType.EMAIL,
        value_hmac=generate_identifier_hmac(
            email,
            settings.identifier_hmac_secret,
        ),
        display_value=email,
        verification_status=VerificationStatus.PENDING,
    )

    db.add(identifier)
    db.commit()
    db.refresh(identifier)

    assert identifier.id is not None
    assert identifier.verification_status == VerificationStatus.PENDING

    otp = generate_otp()

    challenge = OTPChallenge(
        identifier_id=identifier.id,
        otp_hash=hash_otp(otp),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        max_attempts=3,
    )

    db.add(challenge)
    db.commit()
    db.refresh(challenge)

    assert challenge.id is not None
    assert challenge.attempts == 0
    assert challenge.used is False
    assert challenge.otp_hash == hash_otp(otp)
