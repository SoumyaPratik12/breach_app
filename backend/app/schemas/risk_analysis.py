from typing import Literal

from pydantic import BaseModel

from app.schemas.scan import FindingCategory, FindingSeverity


class RiskContributingFactor(BaseModel):
    category: FindingCategory
    severity: FindingSeverity
    count: int


class RiskRecommendation(BaseModel):
    category: FindingCategory
    severity: FindingSeverity
    priority: str
    title: str
    steps: list[str]
    simulated: bool
    verified: bool
    advisory_only: bool


class RiskAnalysisResponse(BaseModel):
    status: Literal["ready", "insufficient_data"]
    risk_score: int | None
    risk_category: str | None
    contributing_factors: list[RiskContributingFactor]
    recommendations: list[RiskRecommendation]
    methodology: str
    limitations: list[str]
    simulated: bool
    scans_analyzed: int
