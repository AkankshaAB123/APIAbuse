"""User, Authentication, and Role Schemas."""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    DEVICE = "DEVICE"


class UserBase(BaseModel):
    user_id: str
    username: str
    role: UserRole
    device_ip: Optional[str] = None
    is_active: bool = True
    created_at: Optional[datetime] = None


class UserInDB(UserBase):
    password_hash: str


class UserPublic(BaseModel):
    user_id: str
    username: str
    role: str
    device_ip: Optional[str] = None
    is_active: bool = True


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, description="Username")
    password: str = Field(..., min_length=1, description="Password")


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    password: str = Field(..., min_length=6, description="Password")
    name: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic
