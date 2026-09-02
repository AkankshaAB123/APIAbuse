"""Detect suspicious use of a valid account after authentication succeeds."""

from collections.abc import Sequence

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)
from ..rules.credentials import (
    ACCOUNT_TAKEOVER_RULE_VERSION,
    AUTH_WINDOW_SECONDS,
    FAILED_AUTH_STATUS_CODES,
    FAILED_LOGIN_BEFORE_SUCCESS_THRESHOLD,
    LOGIN_ENDPOINT_PREFIXES,
    LOGIN_SUCCESS_STATUS_CODES,
)

DETECTOR_ID = "account_takeover"


def _is_login(event: ApiSecurityEvent) -> bool:
    return event.request.endpoint.startswith(LOGIN_ENDPOINT_PREFIXES)


def _is_failed_login(event: ApiSecurityEvent) -> bool:
    return _is_login(event) and event.response.status_code in FAILED_AUTH_STATUS_CODES


def _is_successful_login(event: ApiSecurityEvent) -> bool:
    return (
        _is_login(event)
        and event.identity.is_authenticated
        and event.response.status_code in LOGIN_SUCCESS_STATUS_CODES
    )


def detect_account_takeover(
    event: ApiSecurityEvent, recent_events: Sequence[ApiSecurityEvent] = ()
) -> DetectorResult:
    """Flag suspicious successful authentication or authenticated session reuse."""
    failed_logins = [
        item
        for item in recent_events
        if item.network.source_ip == event.network.source_ip and _is_failed_login(item)
    ]
    session_ip_changed = bool(
        event.identity.is_authenticated
        and event.identity.user_id
        and event.identity.session_id
        and any(
            item.identity.user_id == event.identity.user_id
            and item.identity.session_id == event.identity.session_id
            and item.network.source_ip != event.network.source_ip
            for item in recent_events
        )
    )

    if _is_successful_login(event) and len(failed_logins) >= FAILED_LOGIN_BEFORE_SUCCESS_THRESHOLD:
        return _detected_result(
            event,
            subtype="FAILED_LOGINS_THEN_SUCCESS",
            confidence=0.92,
            severity=Severity.HIGH,
            message=(
                f"Successful login from {event.network.source_ip} followed "
                f"{len(failed_logins)} failed login attempts from the same IP"
            ),
            failed_login_count=len(failed_logins),
        )

    if session_ip_changed:
        return _detected_result(
            event,
            subtype="SESSION_IP_CHANGE",
            confidence=0.75,
            severity=Severity.MEDIUM,
            message=(
                f"Authenticated session {event.identity.session_id} for user "
                f"{event.identity.user_id} was observed from a new source IP"
            ),
            failed_login_count=len(failed_logins),
        )

    return DetectorResult(
        event_id=event.event_id,
        detector_id=DETECTOR_ID,
        detected=False,
        attack_type=None,
        confidence=0.0,
        severity=Severity.LOW,
        metadata={
            "rule_version": ACCOUNT_TAKEOVER_RULE_VERSION,
            "window_seconds": AUTH_WINDOW_SECONDS,
            "failed_login_count": len(failed_logins),
        },
    )


def _detected_result(
    event: ApiSecurityEvent,
    *,
    subtype: str,
    confidence: float,
    severity: Severity,
    message: str,
    failed_login_count: int,
) -> DetectorResult:
    return DetectorResult(
        event_id=event.event_id,
        detector_id=DETECTOR_ID,
        detected=True,
        attack_type=AttackType.ACCOUNT_TAKEOVER,
        confidence=confidence,
        severity=severity,
        evidence=(Evidence(code=subtype, message=message),),
        metadata={
            "rule_version": ACCOUNT_TAKEOVER_RULE_VERSION,
            "window_seconds": AUTH_WINDOW_SECONDS,
            "subtype": subtype,
            "failed_login_count": failed_login_count,
        },
    )
