from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models import User
from app.schemas.scan import ExposureScanResponse
from app.security.auth import get_current_user
from app.services.scan_provider import ScanProvider, simulated_scan_provider
from app.services.scan_service import get_scan_for_user, start_scan


router = APIRouter(tags=["Scans"])


def get_scan_provider() -> ScanProvider:
    return simulated_scan_provider


@router.post(
    "/identifiers/{identifier_id}/scans",
    response_model=ExposureScanResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_identifier_scan(
    identifier_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    provider: ScanProvider = Depends(get_scan_provider),
):
    return start_scan(
        db=db,
        user_id=current_user.id,
        identifier_id=identifier_id,
        provider=provider,
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ExposureScanResponse,
)
def read_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_scan_for_user(
        db=db,
        user_id=current_user.id,
        scan_id=scan_id,
    )
