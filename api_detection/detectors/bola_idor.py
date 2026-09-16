"""Detect broken object-level authorization (BOLA/IDOR)."""

from collections.abc import Sequence

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)
from ..rules.authorization import (
    BOLA_RULE_VERSION,
    NON_OWNED_IDENTIFIERS,
    PRIVILEGED_ROLES,
)

DETECTOR_ID = "bola_idor"


def detect_bola_idor(
    event: ApiSecurityEvent, recent_events: Sequence[ApiSecurityEvent] = ()
) -> DetectorResult:
    """Flag an authenticated non-privileged user accessing another owner's resource."""
    del recent_events

    user_id = str(event.identity.user_id).strip() if event.identity.user_id else None

    # Resolve resource owner: inspect resource context first, then request payload if present
    raw_owner_id = event.resource.owner_id
    if not raw_owner_id and isinstance(event.request.body, dict):
        raw_owner_id = event.request.body.get("target_user_id") or event.request.body.get("owner_id")
    if not raw_owner_id and isinstance(event.request.path_params, dict):
        raw_owner_id = event.request.path_params.get("target_user_id") or event.request.path_params.get("owner_id")

    owner_id = str(raw_owner_id).strip() if raw_owner_id else None

    # Exclude public/system/non-owned identifiers where individual resource ownership is not applicable
    if owner_id and owner_id.lower() in NON_OWNED_IDENTIFIERS:
        owner_id = None

    user_roles = {str(role).lower().strip() for role in event.identity.roles}
    privileged = bool(user_roles & {r.lower() for r in PRIVILEGED_ROLES})

    is_owner_mismatch = bool(user_id and owner_id and user_id != owner_id)
    detected = bool(event.identity.is_authenticated and is_owner_mismatch and not privileged)

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

    resource_type = event.resource.resource_type or "resource"
    resource_id = event.resource.resource_id
    if not resource_id and isinstance(event.request.path_params, dict):
        resource_id = event.request.path_params.get("object_id") or event.request.path_params.get("id")
    if not resource_id and isinstance(event.request.body, dict):
        resource_id = event.request.body.get("object_id") or event.request.body.get("resource_id")

    resource_desc = f"{resource_type} {resource_id}" if resource_id else resource_type

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
                    f"Ownership mismatch: Authenticated user {user_id} requested "
                    f"{resource_desc} owned by {owner_id}"
                ),
            ),
        ),
        metadata={
            "rule_version": BOLA_RULE_VERSION,
            "window_seconds": 0,
            "requesting_user": user_id,
            "resource_owner": owner_id,
        },
    )
