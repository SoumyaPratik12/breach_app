from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.db.database import get_db
from app.models import User
from app.schemas.auth import (
    AuthResponse,
    LoginRequest,
    RegisterRequest,
    UserResponse,
)
from app.security.auth import get_current_user
from app.security.jwt import create_access_token
from app.security.login_rate_limiter import LoginRateLimiter
from app.security.passwords import hash_password, verify_password


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

login_rate_limiter = LoginRateLimiter(
    max_attempts=settings.login_rate_limit_attempts,
    window_seconds=settings.login_rate_limit_window_seconds,
)


@router.post(
    "/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    request: RegisterRequest,
    db: Session = Depends(get_db),
):
    email = request.email.lower().strip()

    existing_user = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = User(
        email=email,
        password_hash=hash_password(request.password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.id)

    return AuthResponse(
        access_token=token,
        token_type="bearer",
    )


@router.post(
    "/login",
    response_model=AuthResponse,
)
def login(
    request: LoginRequest,
    http_request: Request,
    db: Session = Depends(get_db),
):
    client_host = (
        http_request.client.host
        if http_request.client is not None
        else "unknown"
    )
    if login_rate_limiter.is_limited(client_host):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Too many failed login attempts. "
                "Please try again later."
            ),
            headers={
                "Retry-After": str(
                    settings.login_rate_limit_window_seconds
                )
            },
        )

    email = request.email.lower().strip()

    user = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    if user is None or not verify_password(
        request.password,
        user.password_hash,
    ):
        login_rate_limiter.record_failure(client_host)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    token = create_access_token(user.id)

    return AuthResponse(
        access_token=token,
        token_type="bearer",
    )


@router.get(
    "/me",
    response_model=UserResponse,
)
def get_me(
    current_user: User = Depends(get_current_user),
):
    return current_user
