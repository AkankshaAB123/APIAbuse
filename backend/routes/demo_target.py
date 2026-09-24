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
_DEMO_SEARCH_COUNTER = 0
_DEMO_COMMENT_COUNTER = 0
_COUNTER_LOCK = threading.Lock()

DUMMY_VALID_USER = "demo_admin"
DUMMY_VALID_PASS = "SecretPassword123!"


class DemoLoginRequest(BaseModel):
    username: str = Field(..., description="Dummy login username")
    password: str = Field(..., description="Dummy login password")


def get_demo_target_invocation_count() -> int:
    """Return the total number of times any protected demo target was actually executed."""
    with _COUNTER_LOCK:
        return _DEMO_INVOCATION_COUNTER


def get_demo_search_invocation_count() -> int:
    """Return the total number of times the protected demo search target was executed."""
    with _COUNTER_LOCK:
        return _DEMO_SEARCH_COUNTER


def get_demo_comment_invocation_count() -> int:
    """Return the total number of times the protected demo comment target was executed."""
    with _COUNTER_LOCK:
        return _DEMO_COMMENT_COUNTER


def reset_demo_target_invocation_count() -> None:
    """Reset all demo target invocation counters."""
    global _DEMO_INVOCATION_COUNTER, _DEMO_SEARCH_COUNTER, _DEMO_COMMENT_COUNTER
    with _COUNTER_LOCK:
        _DEMO_INVOCATION_COUNTER = 0
        _DEMO_SEARCH_COUNTER = 0
        _DEMO_COMMENT_COUNTER = 0


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


@router.get("/demo-search")
def demo_search(query: str = ""):
    """Controlled harmless disposable search target for SQL injection demo.

    Does NOT connect to a database or execute arbitrary SQL.
    Simply records that the target was reached.
    """
    global _DEMO_INVOCATION_COUNTER, _DEMO_SEARCH_COUNTER
    with _COUNTER_LOCK:
        _DEMO_INVOCATION_COUNTER += 1
        _DEMO_SEARCH_COUNTER += 1
        current_count = _DEMO_INVOCATION_COUNTER
        search_count = _DEMO_SEARCH_COUNTER

    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "message": "Demo search executed safely",
            "query": query,
            "target_invocation_count": current_count,
            "search_invocation_count": search_count,
            "results": [
                {"id": 101, "item": "Synthetic Demo Item Alpha"},
                {"id": 102, "item": "Synthetic Demo Item Beta"},
            ],
        },
    )


@router.get("/demo-comment")
def demo_comment(q: str = "", comment: str = ""):
    """Controlled harmless disposable comment/input target for XSS demo.

    Does NOT execute JavaScript or render attacker-controlled HTML.
    Simply records that the target was reached.
    """
    global _DEMO_INVOCATION_COUNTER, _DEMO_COMMENT_COUNTER
    input_val = q or comment
    with _COUNTER_LOCK:
        _DEMO_INVOCATION_COUNTER += 1
        _DEMO_COMMENT_COUNTER += 1
        current_count = _DEMO_INVOCATION_COUNTER
        comment_count = _DEMO_COMMENT_COUNTER

    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "message": "Demo comment processed safely",
            "input": input_val,
            "target_invocation_count": current_count,
            "comment_invocation_count": comment_count,
        },
    )


@router.get("/demo-target-stats")
def demo_target_stats():
    """Return invocation statistics of the demo targets."""
    with _COUNTER_LOCK:
        return {
            "invocation_count": _DEMO_INVOCATION_COUNTER,
            "search_invocation_count": _DEMO_SEARCH_COUNTER,
            "comment_invocation_count": _DEMO_COMMENT_COUNTER,
        }
