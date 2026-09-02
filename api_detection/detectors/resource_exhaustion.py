"""Detect unusually high request volume against an API endpoint."""

from collections.abc import Sequence

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)
from ..rules.resource_exhaustion import (
    REQUEST_THRESHOLD,
    REQUEST_WINDOW_SECONDS,
    RESOURCE_EXHAUSTION_RULE_VERSION,
)

DETECTOR_ID = "resource_exhaustion"


def detect_resource_exhaustion(
    event: ApiSecurityEvent,
    recent_events: Sequence[ApiSecurityEvent] = (),
) -> DetectorResult:
    """Flag excessive requests from the same IP to the same endpoint."""

    matching_requests = [
        item
        for item in recent_events
        if (
            item.network.source_ip == event.network.source_ip
            and item.request.endpoint == event.request.endpoint
        )
    ]

    request_count = len(matching_requests) + 1

    if request_count >= REQUEST_THRESHOLD:
        return DetectorResult(
            event_id=event.event_id,
            detector_id=DETECTOR_ID,
            detected=True,
            attack_type=AttackType.RESOURCE_EXHAUSTION,
            confidence=0.90,
            severity=Severity.HIGH,
            evidence=(
                Evidence(
                    code="EXCESSIVE_REQUEST_VOLUME",
                    message=(
                        f"{request_count} requests were observed from "
                        f"{event.network.source_ip} to "
                        f"{event.request.endpoint}"
                    ),
                ),
            ),
            metadata={
                "rule_version": RESOURCE_EXHAUSTION_RULE_VERSION,
                "window_seconds": REQUEST_WINDOW_SECONDS,
                "request_count": request_count,
                "threshold": REQUEST_THRESHOLD,
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
            "rule_version": RESOURCE_EXHAUSTION_RULE_VERSION,
            "window_seconds": REQUEST_WINDOW_SECONDS,
            "request_count": request_count,
            "threshold": REQUEST_THRESHOLD,
        },
    )