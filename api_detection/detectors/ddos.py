
"""Detect unusually high distributed request volume against a target."""

from collections.abc import Sequence

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorDomain,
    DetectorResult,
    Evidence,
    Severity,
)


DETECTOR_ID = "ddos"

REQUEST_THRESHOLD = 100
SOURCE_IP_THRESHOLD = 5
DDOS_RULE_VERSION = "1.0"
DDOS_WINDOW_SECONDS = 60


def detect_ddos(
    event: ApiSecurityEvent,
    recent_events: Sequence[ApiSecurityEvent] = (),
) -> DetectorResult:
    """Flag high request volume from multiple source IPs to one target."""

    matching_events = [
        item
        for item in recent_events
        if (
            item.network.destination_ip
            == event.network.destination_ip
            and item.request.endpoint
            == event.request.endpoint
        )
    ]

    all_events = [*matching_events, event]

    request_count = len(all_events)

    source_ips = {
        item.network.source_ip
        for item in all_events
        if item.network.source_ip
    }

    unique_source_count = len(source_ips)

    if (
        request_count >= REQUEST_THRESHOLD
        and unique_source_count >= SOURCE_IP_THRESHOLD
    ):
        return DetectorResult(
            event_id=event.event_id,
            detector_id=DETECTOR_ID,
            detected=True,
            attack_type=AttackType.DDOS,
            confidence=0.95,
            severity=Severity.CRITICAL,
            domain=DetectorDomain.NETWORK,
            evidence=(
                Evidence(
                    code="DISTRIBUTED_HIGH_VOLUME",
                    message=(
                        f"{request_count} requests from "
                        f"{unique_source_count} source IPs were observed "
                        f"against {event.network.destination_ip}"
                    ),
                ),
            ),
            metadata={
                "rule_version": DDOS_RULE_VERSION,
                "window_seconds": DDOS_WINDOW_SECONDS,
                "request_count": request_count,
                "unique_source_ips": unique_source_count,
                "request_threshold": REQUEST_THRESHOLD,
                "source_ip_threshold": SOURCE_IP_THRESHOLD,
            },
        )

    return DetectorResult(
        event_id=event.event_id,
        detector_id=DETECTOR_ID,
        detected=False,
        attack_type=None,
        confidence=0.0,
        severity=Severity.LOW,
        domain=DetectorDomain.NETWORK,
        metadata={
            "rule_version": DDOS_RULE_VERSION,
            "window_seconds": DDOS_WINDOW_SECONDS,
            "request_count": request_count,
            "unique_source_ips": unique_source_count,
            "request_threshold": REQUEST_THRESHOLD,
            "source_ip_threshold": SOURCE_IP_THRESHOLD,
        },
    )
