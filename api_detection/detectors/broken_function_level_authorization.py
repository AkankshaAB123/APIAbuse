"""Detect broken function-level authorization / privilege escalation."""

from collections.abc import Sequence

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)
from ..rules.authorization import (
    BFLA_RULE_VERSION,
    PRIVILEGED_ENDPOINT_PREFIXES,
    PRIVILEGED_ROLES,
)

DETECTOR_ID = "broken_function_level_authorization"


def detect_broken_function_level_authorization(
    event: ApiSecurityEvent, recent_events: Sequence[ApiSecurityEvent] = ()
) -> DetectorResult:
    """Flag a non-privileged authenticated user accessing a privileged route."""
    del recent_events
    endpoint = event.request.endpoint
    is_privileged_endpoint = endpoint.startswith(PRIVILEGED_ENDPOINT_PREFIXES)
    has_privileged_role = bool(set(event.identity.roles) & PRIVILEGED_ROLES)
    detected = (
        event.identity.is_authenticated
        and is_privileged_endpoint
        and not has_privileged_role
    )

    if not detected:
        return DetectorResult(
            event_id=event.event_id,
            detector_id=DETECTOR_ID,
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            metadata={"rule_version": BFLA_RULE_VERSION, "window_seconds": 0},
        )

    severity = Severity.CRITICAL if event.resource.is_sensitive else Severity.HIGH
    return DetectorResult(
        event_id=event.event_id,
        detector_id=DETECTOR_ID,
        detected=True,
        attack_type=AttackType.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
        confidence=0.95,
        severity=severity,
        evidence=(
            Evidence(
                code="PRIVILEGED_ENDPOINT_ACCESS",
                message=(
                    f"User {event.identity.user_id} with roles "
                    f"{list(event.identity.roles)} requested privileged endpoint {endpoint}"
                ),
            ),
        ),
        metadata={"rule_version": BFLA_RULE_VERSION, "window_seconds": 0},
    )
