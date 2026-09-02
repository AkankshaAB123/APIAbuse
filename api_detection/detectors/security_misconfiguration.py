"""Detector for potentially unsafe API configuration."""

from __future__ import annotations

from collections.abc import Sequence

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)


MISCONFIGURATION_ENDPOINT_MARKERS = (
    "/debug",
    "/actuator",
    "/metrics",
    "/swagger",
    "/api-docs",
)


def _is_exposed_configuration_endpoint(
    event: ApiSecurityEvent,
) -> bool:
    """
    Return True when the request targets a potentially
    exposed internal or configuration endpoint.
    """

    endpoint = event.request.endpoint.lower()

    return any(
        marker in endpoint
        for marker in MISCONFIGURATION_ENDPOINT_MARKERS
    )


def detect_security_misconfiguration(
    event: ApiSecurityEvent,
    recent_events: Sequence[ApiSecurityEvent] = (),
) -> DetectorResult:
    """
    Detect requests exposing potentially sensitive
    debugging or configuration endpoints.
    """

    if not _is_exposed_configuration_endpoint(event):
        return DetectorResult(
            event_id=event.event_id,
            detector_id="security_misconfiguration",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            metadata={
                "endpoint": event.request.endpoint,
            },
        )

    return DetectorResult(
        event_id=event.event_id,
        detector_id="security_misconfiguration",
        detected=True,
        attack_type=AttackType.SECURITY_MISCONFIGURATION,
        confidence=0.90,
        severity=Severity.HIGH,
        evidence=(
            Evidence(
                "EXPOSED_CONFIGURATION_ENDPOINT",
                (
                    "Potentially sensitive configuration "
                    f"endpoint accessed: {event.request.endpoint}"
                ),
            ),
        ),
        metadata={
            "endpoint": event.request.endpoint,
        },
    )