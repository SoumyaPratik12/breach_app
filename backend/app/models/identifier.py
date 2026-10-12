from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SQLEnum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class IdentifierType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    NAME = "name"


class VerificationStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"


class Identifier(Base):
    __tablename__ = "identifiers"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    type: Mapped[IdentifierType] = mapped_column(
        SQLEnum(IdentifierType),
        nullable=False,
    )

    value_hmac: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )

    display_value: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
    )

    verification_status: Mapped[VerificationStatus] = mapped_column(
        SQLEnum(VerificationStatus),
        default=VerificationStatus.PENDING,
        nullable=False,
    )

    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
