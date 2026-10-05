"""Authentication Router for ThreatGuard.

Endpoints:
- POST /auth/login: authenticates username/password, returns JWT access token + user details
- GET /auth/me: returns authenticated user info derived from JWT
"""

from fastapi import APIRouter, Depends, HTTPException, status

from backend.dependencies.auth import get_current_user
from backend.schemas.user import LoginRequest, RegisterRequest, TokenResponse, UserInDB, UserPublic
from backend.services.auth_service import authenticate_user, create_access_token, register_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    """Authenticate with username and password.

    Returns a signed JWT access token and public user profile on success.
    Passwords and password hashes are never exposed.
    """
    user = authenticate_user(payload.username, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Encode standard JWT claims: sub = username, role, device_ip
    token_data = {
        "sub": user.username,
        "user_id": user.user_id,
        "role": user.role.value,
        "device_ip": user.device_ip,
    }
    access_token = create_access_token(data=token_data)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserPublic(
            user_id=user.user_id,
            username=user.username,
            role=user.role.value,
            device_ip=user.device_ip,
            is_active=user.is_active,
        ),
    )


@router.get("/me", response_model=UserPublic)
def get_current_user_profile(
    current_user: UserInDB = Depends(get_current_user),
):
    """Retrieve identity profile of currently authenticated token bearer."""
    return UserPublic(
        user_id=current_user.user_id,
        username=current_user.username,
        role=current_user.role.value,
        device_ip=current_user.device_ip,
        is_active=current_user.is_active,
    )

@router.post("/register", response_model=TokenResponse)
def register(payload: RegisterRequest):
    """Register a new analyst account and return a signed JWT token."""
    user = register_user(payload.username, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is already taken",
        )

    token_data = {
        "sub": user.username,
        "user_id": user.user_id,
        "role": user.role.value,
        "device_ip": user.device_ip,
    }
    access_token = create_access_token(data=token_data)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserPublic(
            user_id=user.user_id,
            username=user.username,
            role=user.role.value,
            device_ip=user.device_ip,
            is_active=user.is_active,
        ),
    )

