from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.models import (
    ExposureScan,
    Identifier,
    ScanStatus,
    VerificationStatus,
)
from app.security.login_rate_limiter import InMemoryRateLimiter
from app.services.scan_provider import (
    ScanProvider,
    simulated_scan_provider,
)


scan_rate_limiter = InMemoryRateLimiter(
    max_attempts=settings.scan_rate_limit_attempts,
    window_seconds=settings.scan_rate_limit_window_seconds,
)


def start_scan(
    db: Session,
    user_id: str,
    identifier_id: str,
    provider: ScanProvider = simulated_scan_provider,
) -> ExposureScan:
    identifier = (
        db.query(Identifier)
        .filter(
            Identifier.id == identifier_id,
            Identifier.user_id == user_id,
        )
        .first()
    )
    if identifier is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identifier not found",
        )
    if identifier.verification_status != VerificationStatus.VERIFIED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Identifier must be verified before scanning",
        )
    if not scan_rate_limiter.consume_if_allowed(user_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Scan rate limit exceeded. Please try again later.",
            headers={
                "Retry-After": str(
                    settings.scan_rate_limit_window_seconds
                )
            },
        )

    scan = ExposureScan(
        user_id=user_id,
        identifier_id=identifier.id,
        status=ScanStatus.PENDING,
        is_simulated=True,
        findings=[],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)

    try:
        findings = provider.scan()
        serialized_findings = [
            finding.model_dump(mode="json")
            for finding in findings
        ]
    except Exception:
        scan.status = ScanStatus.FAILED
        scan.error_code = "provider_error"
        scan.findings = []
        scan.completed_at = datetime.now(timezone.utc)
    else:
        scan.findings = serialized_findings
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)
    return scan


def get_scan_for_user(
    db: Session,
    user_id: str,
    scan_id: str,
) -> ExposureScan:
    scan = (
        db.query(ExposureScan)
        .filter(
            ExposureScan.id == scan_id,
            ExposureScan.user_id == user_id,
        )
        .first()
    )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return scan
