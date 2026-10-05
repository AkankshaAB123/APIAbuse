from collections.abc import Iterable

from api_detection.contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorDomain,
    DetectorResult,
    Evidence,
    Severity,
)


PORT_SCAN_THRESHOLD = 100
PORT_SCAN_WINDOW_SECONDS = 60
PORT_SCAN_RULE_VERSION = "1.0"


def detect_port_scanning(
    event: ApiSecurityEvent,
    recent_events: Iterable[ApiSecurityEvent] = (),
) -> DetectorResult:
    """
    Detect a source contacting a large number of unique destination ports
    on the same destination host within a short time window.

    Detection is telemetry-only.
    """
    network = event.network

    if network is None:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="port_scanning",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": PORT_SCAN_RULE_VERSION,
            },
            domain=DetectorDomain.NETWORK,
        )

    destination_ports = set()

    if network.destination_port is not None:
        destination_ports.add(network.destination_port)

    for previous in recent_events:
        previous_network = previous.network

        if previous_network is None:
            continue

        if previous_network.source_ip != network.source_ip:
            continue

        if previous_network.destination_ip != network.destination_ip:
            continue

        if previous_network.destination_port is None:
            continue

        destination_ports.add(previous_network.destination_port)

    unique_ports = len(destination_ports)

    detected = unique_ports >= PORT_SCAN_THRESHOLD

    evidence = ()

    if detected:
        evidence = (
            Evidence(
                code="PORT_SCANNING_MANY_PORTS",
                message=(
                    f"Many destination ports contacted by "
                    f"{network.source_ip}: "
                    f"{unique_ports} unique ports."
                ),
            ),
        )

    confidence = min(
        1.0,
        unique_ports / PORT_SCAN_THRESHOLD,
    )

    severity = Severity.HIGH if detected else Severity.LOW

    return DetectorResult(
        event_id=event.event_id,
        detector_id="port_scanning",
        detected=detected,
        attack_type=AttackType.PORT_SCANNING if detected else None,
        confidence=confidence,
        severity=severity,
        evidence=evidence,
        source="rule",
        metadata={
            "rule_version": PORT_SCAN_RULE_VERSION,
            "threshold": PORT_SCAN_THRESHOLD,
            "window_seconds": PORT_SCAN_WINDOW_SECONDS,
            "unique_ports": unique_ports,
        },
        domain=DetectorDomain.NETWORK,
    )