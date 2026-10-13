from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanStatus


class FindingCategory(str, Enum):
    CREDENTIAL_EXPOSURE = "credential_exposure"
    PUBLIC_PROFILE = "public_profile"


class FindingSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ExposureFinding(BaseModel):
    category: FindingCategory
    severity: FindingSeverity
    description: str
    source: str
    simulated: Literal[True] = True
    verified: Literal[False] = False


class ExposureScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    identifier_id: str
    status: ScanStatus
    is_simulated: bool
    findings: list[ExposureFinding]
    error_code: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
