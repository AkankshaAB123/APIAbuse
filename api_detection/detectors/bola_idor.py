"""Detect broken object-level authorization (BOLA/IDOR)."""

from collections.abc import Sequence

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)
from ..rules.authorization import BOLA_RULE_VERSION, PRIVILEGED_ROLES

DETECTOR_ID = "bola_idor"


def detect_bola_idor(
    event: ApiSecurityEvent, recent_events: Sequence[ApiSecurityEvent] = ()
) -> DetectorResult:
    """Flag an authenticated non-privileged user accessing another owner's resource."""
    del recent_events
    user_id = event.identity.user_id
    owner_id = event.resource.owner_id
    privileged = bool(set(event.identity.roles) & PRIVILEGED_ROLES)
    is_owner_mismatch = bool(user_id and owner_id and user_id != owner_id)
    detected = event.identity.is_authenticated and is_owner_mismatch and not privileged

    if not detected:
        return DetectorResult(
            event_id=event.event_id,
            detector_id=DETECTOR_ID,
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            metadata={"rule_version": BOLA_RULE_VERSION, "window_seconds": 0},
        )

    severity = Severity.CRITICAL if event.resource.is_sensitive else Severity.HIGH
    return DetectorResult(
        event_id=event.event_id,
        detector_id=DETECTOR_ID,
        detected=True,
        attack_type=AttackType.BOLA_IDOR,
        confidence=0.97,
        severity=severity,
        evidence=(
            Evidence(
                code="RESOURCE_OWNER_MISMATCH",
                message=(
                    f"Authenticated user {user_id} requested {event.resource.resource_type} "
                    f"{event.resource.resource_id} owned by {owner_id}"
                ),
            ),
        ),
        metadata={"rule_version": BOLA_RULE_VERSION, "window_seconds": 0},
    )
