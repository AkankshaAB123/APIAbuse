from collections.abc import Iterable

from api_detection.contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorDomain,
    DetectorResult,
    Evidence,
    Severity,
)


BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW_SECONDS = 60
BRUTE_FORCE_RULE_VERSION = "1.0"


def detect_network_brute_force(
    event: ApiSecurityEvent,
    recent_events: Iterable[ApiSecurityEvent] = (),
) -> DetectorResult:
    """
    Detect repeated failed network connection attempts from the same source
    to the same destination/port within a short time window.
    """

    network = event.network

    if network is None:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="network_brute_force",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": BRUTE_FORCE_RULE_VERSION,
            },
            domain=DetectorDomain.NETWORK,
        )

    failed_statuses = {
        "failed",
        "failure",
        "denied",
        "rejected",
    }

    if network.connection_status not in failed_statuses:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="network_brute_force",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": BRUTE_FORCE_RULE_VERSION,
            },
            domain=DetectorDomain.NETWORK,
        )

    failed_attempts = 1

    for previous in recent_events:
        previous_network = previous.network

        if previous_network is None:
            continue

        if previous_network.connection_status not in failed_statuses:
            continue

        if previous_network.source_ip != network.source_ip:
            continue

        if previous_network.destination_ip != network.destination_ip:
            continue

        if previous_network.destination_port != network.destination_port:
            continue

        failed_attempts += 1

    detected = failed_attempts >= BRUTE_FORCE_THRESHOLD

    evidence = ()

    if detected:
        evidence = (
            Evidence(
                code="NETWORK_BRUTE_FORCE_REPEATED_FAILURES",
                message=(
                    f"Repeated failed network connections from "
                    f"{network.source_ip}: "
                    f"{failed_attempts} failures in the observation window."
                ),
            ),
        )

    return DetectorResult(
        event_id=event.event_id,
        detector_id="network_brute_force",
        detected=detected,
        attack_type=AttackType.NETWORK_BRUTE_FORCE if detected else None,
        confidence=min(
            1.0,
            failed_attempts / BRUTE_FORCE_THRESHOLD,
        ),
        severity=Severity.HIGH if detected else Severity.LOW,
        evidence=evidence,
        source="rule",
        metadata={
            "rule_version": BRUTE_FORCE_RULE_VERSION,
            "threshold": BRUTE_FORCE_THRESHOLD,
            "window_seconds": BRUTE_FORCE_WINDOW_SECONDS,
            "failed_attempts": failed_attempts,
        },
        domain=DetectorDomain.NETWORK,
    )