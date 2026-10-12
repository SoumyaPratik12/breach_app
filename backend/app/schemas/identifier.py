from datetime import datetime

from pydantic import BaseModel, Field

from app.models.identifier import IdentifierType, VerificationStatus


class IdentifierCreateRequest(BaseModel):
    type: IdentifierType
    value: str = Field(min_length=1, max_length=320)


class IdentifierResponse(BaseModel):
    id: str
    type: IdentifierType
    display_value: str
    verification_status: VerificationStatus
    verified_at: datetime | None
    created_at: datetime


class OTPRequestResponse(BaseModel):
    message: str
    expires_at: datetime
    dev_otp: str | None = None


class OTPVerifyRequest(BaseModel):
    otp: str = Field(min_length=6, max_length=6)


class OTPVerifyResponse(BaseModel):
    message: str
    verification_status: VerificationStatus
