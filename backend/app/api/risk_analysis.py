from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models import (
    ExposureScan,
    Identifier,
    ScanStatus,
    User,
    VerificationStatus,
)
from app.risk.recommendations import recommend_for_findings
from app.risk.scoring import summarize_findings
from app.schemas.risk_analysis import (
    RiskAnalysisResponse,
    RiskContributingFactor,
)
from app.schemas.scan import ExposureFinding
from app.security.auth import get_current_user


router = APIRouter(tags=["Risk Analysis"])

METHODOLOGY = (
    "Explainable heuristic: findings are weighted low=5, medium=15, "
    "high=25, summed across eligible completed scans, and capped at 100. "
    "Scores map to categories as follows: 0=none, 1-24=low, 25-49=medium, "
    "50-74=high, and 75-100=critical."
)
LIMITATIONS = [
    "This is a product heuristic, not a trained or validated AI prediction model.",
    "Results reflect only recorded completed scans and cannot establish "
    "whether information is present in real-world sources.",
    "Scan coverage is limited to the configured provider; absence of findings "
    "does not mean an identifier is safe.",
    "Recommendations are advisory and findings should be independently verified.",
]


def get_risk_analysis(
    db: Session,
    user_id: str,
) -> RiskAnalysisResponse:
    scans = (
        db.query(ExposureScan)
        .join(Identifier, ExposureScan.identifier_id == Identifier.id)
        .filter(
            ExposureScan.user_id == user_id,
            Identifier.user_id == user_id,
            Identifier.verification_status == VerificationStatus.VERIFIED,
            ExposureScan.status == ScanStatus.COMPLETED,
        )
        .order_by(ExposureScan.completed_at, ExposureScan.created_at)
        .all()
    )
    if not scans:
        return RiskAnalysisResponse(
            status="insufficient_data",
            risk_score=None,
            risk_category=None,
            contributing_factors=[],
            recommendations=[],
            methodology=METHODOLOGY,
            limitations=LIMITATIONS,
            simulated=False,
            scans_analyzed=0,
        )

    findings = [
        ExposureFinding.model_validate(finding)
        for scan in scans
        for finding in scan.findings
    ]
    summary = summarize_findings(findings)

    factor_counts = Counter(
        (finding.category, finding.severity)
        for finding in summary["prioritized_findings"]
    )
    contributing_factors = [
        RiskContributingFactor(
            category=category,
            severity=severity,
            count=count,
        )
        for (category, severity), count in factor_counts.items()
    ]

    recommendation_by_category = {}
    for recommendation in recommend_for_findings(
        summary["prioritized_findings"]
    ):
        recommendation_by_category.setdefault(
            recommendation["category"],
            recommendation,
        )

    return RiskAnalysisResponse(
        status="ready",
        risk_score=summary["risk_score"],
        risk_category=summary["risk_level"],
        contributing_factors=contributing_factors,
        recommendations=list(recommendation_by_category.values())[:3],
        methodology=METHODOLOGY,
        limitations=LIMITATIONS,
        simulated=any(scan.is_simulated for scan in scans)
        or any(finding.simulated for finding in findings),
        scans_analyzed=len(scans),
    )


@router.get(
    "/risk-analysis",
    response_model=RiskAnalysisResponse,
)
def read_risk_analysis(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_risk_analysis(db=db, user_id=current_user.id)
