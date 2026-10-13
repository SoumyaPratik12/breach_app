from datetime import datetime
import re

from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    TypeAdapter,
    ValidationError,
    ValidationInfo,
    field_serializer,
    field_validator,
)

from app.models.identifier import IdentifierType, VerificationStatus
from app.security.identifier_encryption import decrypt_identifier
from app.security.masking import mask_identifier


class IdentifierCreateRequest(BaseModel):
    type: IdentifierType
    value: str = Field(min_length=1, max_length=320)

    @field_validator("value")
    @classmethod
    def validate_identifier_value(
        cls,
        value: str,
        info: ValidationInfo,
    ) -> str:
        identifier_type = info.data.get("type")
        if identifier_type == IdentifierType.EMAIL:
            try:
                TypeAdapter(EmailStr).validate_python(value)
            except ValidationError as exc:
                raise ValueError("A valid email address is required") from exc
        elif identifier_type == IdentifierType.PHONE:
            if re.fullmatch(r"\+?[0-9 ()-]+", value) is None:
                raise ValueError("Phone number contains unsupported characters")

            digit_count = sum(
                character in "0123456789" for character in value
            )
            if not 7 <= digit_count <= 15:
                raise ValueError(
                    "Phone number must contain between 7 and 15 digits"
                )
        return value


class IdentifierResponse(BaseModel):
    id: str
    type: IdentifierType
    display_value: str
    verification_status: VerificationStatus
    verified_at: datetime | None
    created_at: datetime

    @field_serializer("display_value")
    def serialize_display_value(self, value: str) -> str:
        return mask_identifier(self.type, decrypt_identifier(value))


class OTPRequestResponse(BaseModel):
    message: str
    expires_at: datetime
    dev_otp: str | None = None


class OTPVerifyRequest(BaseModel):
    otp: str = Field(min_length=6, max_length=6)


class OTPVerifyResponse(BaseModel):
    message: str
    verification_status: VerificationStatus
