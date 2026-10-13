from datetime import datetime, timezone

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import ExposureScan, ScanStatus


def recover_stale_scans(db: Session, cutoff: datetime) -> int:
    """Mark RUNNING scans older than cutoff as interrupted."""
    try:
        stale_scans = (
            db.query(ExposureScan)
            .filter(
                ExposureScan.status == ScanStatus.RUNNING,
                ExposureScan.started_at.is_not(None),
                ExposureScan.started_at < cutoff,
            )
            .all()
        )

        if not stale_scans:
            return 0

        completed_at = datetime.now(timezone.utc)

        for scan in stale_scans:
            scan.status = ScanStatus.FAILED
            scan.error_code = "scan_interrupted"
            scan.completed_at = completed_at

        db.commit()
        return len(stale_scans)

    except SQLAlchemyError:
        db.rollback()
        raise
