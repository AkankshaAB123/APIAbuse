"""Controlled Disposable Demo Target Endpoint.

Provides a safe, dummy authentication endpoint for the controlled two-laptop demonstration.
Maintains an in-memory invocation counter strictly for proving enforcement behavior
(proving that blocked requests never reach the target).
"""

import threading
from typing import Optional
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

router = APIRouter(tags=["Demo Target"])

_DEMO_INVOCATION_COUNTER = 0
_COUNTER_LOCK = threading.Lock()

DUMMY_VALID_USER = "demo_admin"
DUMMY_VALID_PASS = "SecretPassword123!"


class DemoLoginRequest(BaseModel):
    username: str = Field(..., description="Dummy login username")
    password: str = Field(..., description="Dummy login password")


def get_demo_target_invocation_count() -> int:
    """Return the total number of times the protected demo target was actually executed."""
    with _COUNTER_LOCK:
        return _DEMO_INVOCATION_COUNTER


def reset_demo_target_invocation_count() -> None:
    """Reset the demo target invocation counter."""
    global _DEMO_INVOCATION_COUNTER
    with _COUNTER_LOCK:
        _DEMO_INVOCATION_COUNTER = 0


@router.post("/demo-login")
def demo_login(payload: DemoLoginRequest):
    """Controlled dummy login endpoint.

    Uses strictly dummy credentials.
    Returns 200 OK for valid dummy credentials, 401 Unauthorized for invalid dummy credentials.
    Increments execution counter upon each arrival.
    """
    global _DEMO_INVOCATION_COUNTER
    with _COUNTER_LOCK:
        _DEMO_INVOCATION_COUNTER += 1
        current_count = _DEMO_INVOCATION_COUNTER

    if payload.username == DUMMY_VALID_USER and payload.password == DUMMY_VALID_PASS:
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Demo authenticated successfully",
                "user": payload.username,
                "target_invocation_count": current_count,
            },
        )

    return JSONResponse(
        status_code=401,
        content={
            "status": "unauthorized",
            "message": "Invalid demo credentials",
            "target_invocation_count": current_count,
        },
    )


@router.get("/demo-target-stats")
def demo_target_stats():
    """Return invocation statistics of the demo target."""
    return {
        "invocation_count": get_demo_target_invocation_count(),
    }
