"""Detector for suspicious API endpoint enumeration."""

from __future__ import annotations

from collections.abc import Sequence

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)

ENDPOINT_ENUMERATION_THRESHOLD = 5


def detect_endpoint_enumeration(
    event: ApiSecurityEvent,
    recent_events: Sequence[ApiSecurityEvent] = (),
) -> DetectorResult:
    """
    Detect attempts to access many different API endpoints
    from the same source IP.
    """

    source_ip = event.network.source_ip

    accessed_endpoints = {
        previous_event.request.endpoint
        for previous_event in recent_events
        if previous_event.network.source_ip == source_ip
    }

    accessed_endpoints.add(event.request.endpoint)

    endpoint_count = len(accessed_endpoints)

    detected = (
        endpoint_count >= ENDPOINT_ENUMERATION_THRESHOLD
    )

    if detected:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="endpoint_enumeration",
            detected=True,
            attack_type=AttackType.ENDPOINT_ENUMERATION,
            confidence=0.85,
            severity=Severity.HIGH,
            evidence=(
                Evidence(
                    "MULTIPLE_ENDPOINTS_ACCESSED",
                    (
                        f"Source IP {source_ip} accessed "
                        f"{endpoint_count} different endpoints."
                    ),
                ),
            ),
            metadata={
                "endpoint_count": endpoint_count,
                "threshold": ENDPOINT_ENUMERATION_THRESHOLD,
            },
        )

    return DetectorResult(
        event_id=event.event_id,
        detector_id="endpoint_enumeration",
        detected=False,
        attack_type=None,
        confidence=0.0,
        severity=Severity.LOW,
        metadata={
            "endpoint_count": endpoint_count,
            "threshold": ENDPOINT_ENUMERATION_THRESHOLD,
        },
    )