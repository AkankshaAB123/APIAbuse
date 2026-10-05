from collections.abc import Iterable

from api_detection.contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorDomain,
    DetectorResult,
    Evidence,
    Severity,
)


KEYLOGGING_RULE_VERSION = "1.0"


def detect_keylogging(
    event: ApiSecurityEvent,
    recent_events: Iterable[ApiSecurityEvent] = (),
) -> DetectorResult:
    """
    Detect endpoint telemetry indicating a keyboard hook.

    Detection is telemetry-only. This detector does not install,
    execute, or interact with a keylogger.
    """
    endpoint = event.endpoint

    if endpoint is None:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="keylogging",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": KEYLOGGING_RULE_VERSION,
            },
            domain=DetectorDomain.ENDPOINT,
        )

    if endpoint.keyboard_hook is not True:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="keylogging",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": KEYLOGGING_RULE_VERSION,
            },
            domain=DetectorDomain.ENDPOINT,
        )

    evidence = (
        Evidence(
            code="KEYLOGGING_KEYBOARD_HOOK",
            message=(
                "Endpoint telemetry indicates that a keyboard hook "
                "was observed."
            ),
        ),
    )

    return DetectorResult(
        event_id=event.event_id,
        detector_id="keylogging",
        detected=True,
        attack_type=AttackType.KEYLOGGING,
        confidence=1.0,
        severity=Severity.HIGH,
        evidence=evidence,
        source="rule",
        metadata={
            "rule_version": KEYLOGGING_RULE_VERSION,
            "keyboard_hook": endpoint.keyboard_hook,
            "hostname": endpoint.hostname,
            "process_name": endpoint.process_name,
            "process_id": endpoint.process_id,
        },
        domain=DetectorDomain.ENDPOINT,
    )