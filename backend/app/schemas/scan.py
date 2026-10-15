from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, computed_field

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

    def _get_risk_summary(self) -> dict:
        # Import lazily to avoid a circular import: scoring imports ExposureFinding.
        from app.risk.scoring import summarize_findings

        return summarize_findings(self.findings)

    @computed_field
    @property
    def risk_score(self) -> int | None:
        if self.status != ScanStatus.COMPLETED:
            return None
        return self._get_risk_summary()["risk_score"]

    @computed_field
    @property
    def risk_level(self) -> str:
        if self.status != ScanStatus.COMPLETED:
            return "unavailable"
        return self._get_risk_summary()["risk_level"]

    @computed_field
    @property
    def severity_counts(self) -> dict[str, int]:
        return self._get_risk_summary()["severity_counts"]

    @computed_field
    @property
    def prioritized_findings(self) -> list[ExposureFinding]:
        if self.status != ScanStatus.COMPLETED:
            return []
        return self._get_risk_summary()["prioritized_findings"]
