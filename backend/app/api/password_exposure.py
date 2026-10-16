from fastapi import APIRouter, Depends, HTTPException, status

from app.config.settings import settings
from app.models import User
from app.schemas.password_exposure import (
    PasswordExposureRequest,
    PasswordExposureResponse,
)
from app.security.auth import get_current_user
from app.security.login_rate_limiter import InMemoryRateLimiter
from app.services.password_exposure import (
    PasswordExposureProviderError,
    check_password_exposure,
)

router = APIRouter(prefix="/password-exposure", tags=["Password Exposure"])

password_check_rate_limiter = InMemoryRateLimiter(
    max_attempts=settings.scan_rate_limit_attempts,
    window_seconds=settings.scan_rate_limit_window_seconds,
)


@router.post(
    "/check",
    response_model=PasswordExposureResponse,
)
def check_password(
    payload: PasswordExposureRequest,
    current_user: User = Depends(get_current_user),
):
    # The authenticated user's ID is used only for rate limiting.
    reservation = password_check_rate_limiter.reserve_if_allowed(
        current_user.id
    )
    if reservation is None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Password check rate limit exceeded. Please try again later.",
            headers={
                "Retry-After": str(
                    settings.scan_rate_limit_window_seconds
                )
            },
        )

    try:
        count = check_password_exposure(
            payload.password.get_secret_value()
        )
    except PasswordExposureProviderError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Password exposure service is temporarily unavailable",
        ) from None

    return PasswordExposureResponse(
        exposed=count > 0,
        occurrence_count=count,
    )