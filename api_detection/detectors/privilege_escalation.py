from collections.abc import Iterable

from api_detection.contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorDomain,
    DetectorResult,
    Evidence,
    Severity,
)


PRIVILEGE_ESCALATION_RULE_VERSION = "1.0"


PRIVILEGE_ESCALATION_COMMAND_INDICATORS = (
    "sudo ",
    "runas ",
    "whoami /priv",
    "net localgroup administrators",
    "net localgroup admin",
    "setuid",
    "setgid",
    "chmod +s",
    "chmod 4755",
    "pkexec",
)


def detect_privilege_escalation(
    event: ApiSecurityEvent,
    recent_events: Iterable[ApiSecurityEvent] = (),
) -> DetectorResult:
    """
    Detect endpoint telemetry indicating possible privilege escalation.

    Detection is telemetry-only. This detector does not execute commands,
    change privileges, modify permissions, or exploit vulnerabilities.
    """
    endpoint = event.endpoint

    if endpoint is None:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="privilege_escalation",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": PRIVILEGE_ESCALATION_RULE_VERSION,
            },
            domain=DetectorDomain.ENDPOINT,
        )

    command_line = (
        endpoint.command_line.lower()
        if endpoint.command_line
        else ""
    )

    privilege_level = (
        endpoint.privilege_level.lower()
        if endpoint.privilege_level
        else ""
    )

    elevated = endpoint.elevated is True

    command_indicator = next(
        (
            indicator
            for indicator in PRIVILEGE_ESCALATION_COMMAND_INDICATORS
            if indicator in command_line
        ),
        None,
    )

    privileged_context = privilege_level in {
        "admin",
        "administrator",
        "root",
        "system",
        "high",
    }

    signal_count = sum(
        (
            command_indicator is not None,
            privileged_context,
            elevated,
        )
    )

    if signal_count < 2:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="privilege_escalation",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": PRIVILEGE_ESCALATION_RULE_VERSION,
                "command_line": endpoint.command_line,
                "privilege_level": endpoint.privilege_level,
                "elevated": endpoint.elevated,
                "command_indicator": command_indicator,
                "privileged_context": privileged_context,
                "signal_count": signal_count,
            },
            domain=DetectorDomain.ENDPOINT,
        )

    evidence = []

    if command_indicator is not None:
        evidence.append(
            Evidence(
                code="PRIVILEGE_ESCALATION_COMMAND",
                message=(
                    "Endpoint telemetry contains a command-line "
                    "pattern associated with privilege escalation."
                ),
            )
        )

    if privileged_context:
        evidence.append(
            Evidence(
                code="PRIVILEGED_CONTEXT",
                message=(
                    "Endpoint telemetry indicates execution in a "
                    f"privileged context: {endpoint.privilege_level}."
                ),
            )
        )

    if elevated:
        evidence.append(
            Evidence(
                code="ELEVATED_EXECUTION",
                message=(
                    "Endpoint telemetry indicates that the process "
                    "executed with elevated privileges."
                ),
            )
        )

    confidence = min(
        0.72 + (signal_count * 0.08),
        0.96,
    )

    return DetectorResult(
        event_id=event.event_id,
        detector_id="privilege_escalation",
        detected=True,
        attack_type=AttackType.PRIVILEGE_ESCALATION,
        confidence=confidence,
        severity=Severity.CRITICAL,
        evidence=tuple(evidence),
        source="rule",
        metadata={
            "rule_version": PRIVILEGE_ESCALATION_RULE_VERSION,
            "process_name": endpoint.process_name,
            "process_id": endpoint.process_id,
            "parent_process": endpoint.parent_process,
            "executable_path": endpoint.executable_path,
            "command_line": endpoint.command_line,
            "privilege_level": endpoint.privilege_level,
            "elevated": endpoint.elevated,
            "command_indicator": command_indicator,
            "privileged_context": privileged_context,
            "signal_count": signal_count,
        },
        domain=DetectorDomain.ENDPOINT,
    )