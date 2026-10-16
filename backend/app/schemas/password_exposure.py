from pydantic import BaseModel, Field, SecretStr


class PasswordExposureRequest(BaseModel):
    password: SecretStr = Field(min_length=1, max_length=1024)


class PasswordExposureResponse(BaseModel):
    exposed: bool
    occurrence_count: int = Field(ge=0)
    source: str = "Have I Been Pwned Pwned Passwords"