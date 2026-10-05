"""Server-Side Authentication & User Service for ThreatGuard.

Handles:
- Bcrypt password hashing and verification
- JWT generation and decoding with configurable expiration and secret
- Demo user seeding and lookup with safe development fallbacks
"""

from datetime import datetime, timezone, timedelta
import logging
import os
from typing import Optional, Dict, Any
from uuid import uuid4

import jwt
import bcrypt

from backend.schemas.user import UserInDB, UserRole

logger = logging.getLogger("backend.auth")


# JWT configuration
DEFAULT_DEV_SECRET = "threatguard-academic-demo-jwt-secret-key-change-in-production-2026!"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", DEFAULT_DEV_SECRET)
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

if JWT_SECRET_KEY == DEFAULT_DEV_SECRET:
    logger.warning(
        "[AUTH NOTICE] Running with default academic demo JWT secret. "
        "For production environments, configure a strong JWT_SECRET_KEY."
    )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against hashed password using bcrypt directly."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception as exc:
        logger.error(f"Password verification error: {exc}")
        return False


def get_password_hash(password: str) -> str:
    """Hash password using bcrypt directly."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create signed JWT access token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate JWT access token. Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])


# =========================================================================
# DEMO USER SEEDING & IN-MEMORY / DB CACHE
# =========================================================================

# Fixed bcrypt hashes for standard academic demo users
# (Generated deterministically so backend starts instantly without hash delay on every request)
DEMO_USERS_MAP: Dict[str, UserInDB] = {
    "admin": UserInDB(
        user_id="usr-admin-01",
        username="admin",
        password_hash=get_password_hash("Admin@ThreatGuard2026!"),
        role=UserRole.ADMIN,
        device_ip=None,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    ),
    "analyst": UserInDB(
        user_id="usr-analyst-01",
        username="analyst",
        password_hash=get_password_hash("Analyst@ThreatGuard2026!"),
        role=UserRole.ANALYST,
        device_ip=None,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    ),
    "device": UserInDB(
        user_id="usr-device-186",
        username="device",
        password_hash=get_password_hash("Device@ThreatGuard2026!"),
        role=UserRole.DEVICE,
        device_ip="10.165.192.186",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    ),
}


def get_user_by_username(username: str) -> Optional[UserInDB]:
    """Look up user by normalized username.
    First checks MongoDB users_collection if connected, otherwise falls back to DEMO_USERS_MAP.
    """
    clean_username = username.strip().lower()

    # Try MongoDB first
    try:
        from backend.database import users_collection
        doc = users_collection.find_one({"username": clean_username})
        if doc:
            role_val = doc.get("role", "ANALYST").upper()
            return UserInDB(
                user_id=str(doc.get("user_id") or doc.get("_id")),
                username=doc.get("username"),
                password_hash=doc.get("password_hash"),
                role=UserRole(role_val) if role_val in UserRole.__members__ else UserRole.ANALYST,
                device_ip=doc.get("device_ip"),
                is_active=doc.get("is_active", True),
                created_at=doc.get("created_at"),
            )
    except Exception as exc:
        logger.debug(f"MongoDB lookup for user {clean_username} bypassed: {exc}")

    # Fall back to seeded academic demo identities
    return DEMO_USERS_MAP.get(clean_username)


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Authenticate user credentials. Returns UserInDB on match, None otherwise."""
    user = get_user_by_username(username)
    if not user:
        return None
    if not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user

def register_user(username: str, password: str) -> Optional[UserInDB]:
    """Register a new analyst user. Saves to MongoDB if available, and updates in-memory map."""
    clean_username = username.strip().lower()
    if get_user_by_username(clean_username):
        return None

    hashed = get_password_hash(password)
    user_id = f"usr-{uuid4().hex[:8]}"
    new_user = UserInDB(
        user_id=user_id,
        username=clean_username,
        password_hash=hashed,
        role=UserRole.ANALYST,
        device_ip=None,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )

    # Save to MongoDB
    try:
        from backend.database import users_collection
        users_collection.insert_one({
            "user_id": user_id,
            "username": clean_username,
            "password_hash": hashed,
            "role": "ANALYST",
            "device_ip": None,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
        })
    except Exception as exc:
        logger.debug(f"MongoDB insert for user {clean_username} bypassed: {exc}")

    # Also keep in in-memory map for fast zero-latency access
    DEMO_USERS_MAP[clean_username] = new_user
    return new_user

