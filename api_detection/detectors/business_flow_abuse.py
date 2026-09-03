"""Detector for abnormal repetition of sensitive business actions."""

from __future__ import annotations

from collections.abc import Sequence

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)


BUSINESS_FLOW_THRESHOLD = 5

SENSITIVE_ENDPOINT_PREFIXES = (
    "/api/orders",
    "/api/payments",
    "/api/transactions",
    "/api/checkout",
)


def _is_sensitive_business_action(
    event: ApiSecurityEvent,
) -> bool:
    """
    Return True when the event targets an endpoint
    representing an important business operation.
    """

    endpoint = event.request.endpoint

    return endpoint.startswith(
        SENSITIVE_ENDPOINT_PREFIXES
    )


def detect_business_flow_abuse(
    event: ApiSecurityEvent,
    recent_events: Sequence[ApiSecurityEvent] = (),
) -> DetectorResult:
    """
    Detect excessive repetition of sensitive business actions
    by the same authenticated user.
    """

    user_id = event.identity.user_id

    if (
        not event.identity.is_authenticated
        or user_id is None
        or not _is_sensitive_business_action(event)
    ):
        return DetectorResult(
            event_id=event.event_id,
            detector_id="business_flow_abuse",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            metadata={
                "action_count": 0,
                "threshold": BUSINESS_FLOW_THRESHOLD,
            },
        )

    matching_events = [
        previous_event
        for previous_event in recent_events
        if (
            previous_event.identity.user_id == user_id
            and _is_sensitive_business_action(previous_event)
        )
    ]

    action_count = len(matching_events) + 1

    detected = action_count >= BUSINESS_FLOW_THRESHOLD

    if detected:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="business_flow_abuse",
            detected=True,
            attack_type=AttackType.BUSINESS_FLOW_ABUSE,
            confidence=0.85,
            severity=Severity.HIGH,
            evidence=(
                Evidence(
                    "EXCESSIVE_BUSINESS_ACTIONS",
                    (
                        f"User {user_id} performed "
                        f"{action_count} sensitive business actions."
                    ),
                ),
            ),
            metadata={
                "action_count": action_count,
                "threshold": BUSINESS_FLOW_THRESHOLD,
            },
        )

    return DetectorResult(
        event_id=event.event_id,
        detector_id="business_flow_abuse",
        detected=False,
        attack_type=None,
        confidence=0.0,
        severity=Severity.LOW,
        metadata={
            "action_count": action_count,
            "threshold": BUSINESS_FLOW_THRESHOLD,
        },
    )