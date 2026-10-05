"""FastAPI Authentication & RBAC Dependencies.

Provides reusable server-side authorization guards:
- get_current_user: validates Bearer JWT token, checks activity status
- require_authenticated_user: alias/convenience for any active user
- require_admin: restricts to ADMIN role
- require_analyst: restricts to ANALYST or ADMIN role
- require_device: restricts to DEVICE role
- require_roles(*roles): generic role checker
"""

from typing import List, Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt

from backend.schemas.user import UserInDB, UserRole
from backend.services.auth_service import decode_access_token, get_user_by_username

# HTTPBearer extracts "Authorization: Bearer <token>"
security_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> UserInDB:
    """Validate JWT access token and return current active UserInDB.
    Rejects missing, malformed, expired, or inactive tokens with HTTP 401.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        username: Optional[str] = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please re-authenticate.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user_by_username(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_authenticated_user(
    current_user: UserInDB = Depends(get_current_user),
) -> UserInDB:
    """Ensure caller is any valid authenticated user."""
    return current_user


def require_roles(*allowed_roles: UserRole):
    """Factory dependency: returns user if their role is in allowed_roles, otherwise 403."""
    def _role_checker(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role in {[r.value for r in allowed_roles]}, but user has {current_user.role.value}.",
            )
        return current_user

    return _role_checker


def require_admin(
    current_user: UserInDB = Depends(require_roles(UserRole.ADMIN)),
) -> UserInDB:
    """Restrict route strictly to ADMIN."""
    return current_user


def require_analyst(
    current_user: UserInDB = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
) -> UserInDB:
    """Restrict route to SOC staff (ADMIN or ANALYST)."""
    return current_user


def require_device(
    current_user: UserInDB = Depends(require_roles(UserRole.DEVICE)),
) -> UserInDB:
    """Restrict route strictly to registered protected DEVICE."""
    return current_user
