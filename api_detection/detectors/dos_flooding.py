from collections.abc import Iterable

from api_detection.contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorDomain,
    DetectorResult,
    Evidence,
    Severity,
)


DOS_FLOODING_THRESHOLD = 100
DOS_FLOODING_WINDOW_SECONDS = 60
DOS_FLOODING_RULE_VERSION = "1.0"


def detect_dos_flooding(
    event: ApiSecurityEvent,
    recent_events: Iterable[ApiSecurityEvent] = (),
) -> DetectorResult:
    """
    Detect a high volume of network events from the same source
    toward the same destination within a short time window.

    Detection is telemetry-only.
    """
    network = event.network

    if network is None:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="dos_flooding",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": DOS_FLOODING_RULE_VERSION,
            },
            domain=DetectorDomain.NETWORK,
        )

    matching_events = []

    for previous in recent_events:
        previous_network = previous.network

        if previous_network is None:
            continue

        if previous_network.source_ip != network.source_ip:
            continue

        if previous_network.destination_ip != network.destination_ip:
            continue

        matching_events.append(previous)

    request_count = len(matching_events) + 1

    detected = request_count >= DOS_FLOODING_THRESHOLD

    evidence = ()

    if detected:
        evidence = (
            Evidence(
                code="DOS_FLOODING_HIGH_VOLUME",
                message=(
                    f"High request volume detected from {network.source_ip}: "
                    f"{request_count} requests in the observation window."
                ),
            ),
        )

    confidence = min(
        1.0,
        request_count / DOS_FLOODING_THRESHOLD,
    )

    severity = Severity.HIGH if detected else Severity.LOW

    return DetectorResult(
        event_id=event.event_id,
        detector_id="dos_flooding",
        detected=detected,
        attack_type=AttackType.DOS_FLOODING if detected else None,
        confidence=confidence,
        severity=severity,
        evidence=evidence,
        source="rule",
        metadata={
            "rule_version": DOS_FLOODING_RULE_VERSION,
            "threshold": DOS_FLOODING_THRESHOLD,
            "window_seconds": DOS_FLOODING_WINDOW_SECONDS,
            "request_count": request_count,
        },
        domain=DetectorDomain.NETWORK,
    )