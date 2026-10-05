"""Detect brute-force and credential-stuffing login patterns."""

from collections.abc import Sequence
from typing import Any

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)
from ..rules.credentials import (
    AUTH_WINDOW_SECONDS,
    BRUTE_FORCE_THRESHOLD,
    CREDENTIAL_RULE_VERSION,
    CREDENTIAL_STUFFING_ACCOUNT_THRESHOLD,
    FAILED_AUTH_STATUS_CODES,
    LOGIN_ENDPOINT_PREFIXES,
)

DETECTOR_ID = "credential_attacks"


def _is_failed_login(event: ApiSecurityEvent) -> bool:
    return (
        event.request.endpoint.startswith(LOGIN_ENDPOINT_PREFIXES)
        and event.response.status_code in FAILED_AUTH_STATUS_CODES
    )


def _login_identifier(event: ApiSecurityEvent) -> str | None:
    body: Any = event.request.body
    if not isinstance(body, dict):
        return None
    for key in ("username", "email", "user_id"):
        value = body.get(key)
        if value:
            return str(value)
    return None


def detect_credential_attacks(
    event: ApiSecurityEvent, recent_events: Sequence[ApiSecurityEvent] = ()
) -> DetectorResult:
    """Detect a burst of failed logins from one source IP.

    ``recent_events`` must contain the previous five-minute window; the backend
    will eventually query that window from its event store.
    """
    relevant_events = [
        item
        for item in [*recent_events, event]
        if item.network.source_ip == event.network.source_ip and _is_failed_login(item)
    ]
    attempted_accounts = {
        identifier
        for item in relevant_events
        if (identifier := _login_identifier(item)) is not None
    }
    failed_attempts = len(relevant_events)

    if failed_attempts >= BRUTE_FORCE_THRESHOLD:
        is_stuffing = len(attempted_accounts) >= CREDENTIAL_STUFFING_ACCOUNT_THRESHOLD
        subtype = "CREDENTIAL_STUFFING" if is_stuffing else "BRUTE_FORCE"
        evidence_message = (
            f"Source IP {event.network.source_ip} made {failed_attempts} failed login attempts "
            f"against {len(attempted_accounts)} account(s) in the recent window"
        )
        return DetectorResult(
            event_id=event.event_id,
            detector_id=DETECTOR_ID,
            detected=True,
            attack_type=AttackType.CREDENTIAL_ATTACK,
            confidence=0.95 if is_stuffing else 0.93,
            severity=Severity.HIGH,
            evidence=(Evidence(code=subtype, message=evidence_message),),
            metadata={
                "rule_version": CREDENTIAL_RULE_VERSION,
                "window_seconds": AUTH_WINDOW_SECONDS,
                "subtype": subtype,
                "failed_attempts": failed_attempts,
                "unique_accounts": len(attempted_accounts),
            },
        )

    return DetectorResult(
        event_id=event.event_id,
        detector_id=DETECTOR_ID,
        detected=False,
        attack_type=None,
        confidence=0.0,
        severity=Severity.LOW,
        metadata={
            "rule_version": CREDENTIAL_RULE_VERSION,
            "window_seconds": AUTH_WINDOW_SECONDS,
            "failed_attempts": failed_attempts,
        },
    )
