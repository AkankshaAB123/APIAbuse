from collections.abc import Iterable

from api_detection.contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorDomain,
    DetectorResult,
    Evidence,
    Severity,
)


SUSPICIOUS_PROCESS_EXECUTION_RULE_VERSION = "1.0"


SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
}


def detect_suspicious_process_execution(
    event: ApiSecurityEvent,
    recent_events: Iterable[ApiSecurityEvent] = (),
) -> DetectorResult:
    """
    Detect endpoint telemetry indicating suspicious process execution.

    Detection is telemetry-only. This detector does not execute,
    launch, or interact with any process.
    """
    endpoint = event.endpoint

    if endpoint is None:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="suspicious_process_execution",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": (
                    SUSPICIOUS_PROCESS_EXECUTION_RULE_VERSION
                ),
            },
            domain=DetectorDomain.ENDPOINT,
        )

    process_name = (
        endpoint.process_name.lower()
        if endpoint.process_name
        else ""
    )

    command_line = (
        endpoint.command_line.lower()
        if endpoint.command_line
        else ""
    )

    suspicious_process = process_name in SUSPICIOUS_PROCESS_NAMES

    suspicious_command = any(
        indicator in command_line
        for indicator in (
            "-enc",
            "encodedcommand",
            "downloadstring",
            "invoke-expression",
            "iex ",
            "bypass",
            "hidden",
        )
    )

    if not suspicious_process and not suspicious_command:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="suspicious_process_execution",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": (
                    SUSPICIOUS_PROCESS_EXECUTION_RULE_VERSION
                ),
                "process_name": endpoint.process_name,
                "command_line": endpoint.command_line,
            },
            domain=DetectorDomain.ENDPOINT,
        )

    evidence = []

    if suspicious_process:
        evidence.append(
            Evidence(
                code="SUSPICIOUS_PROCESS_NAME",
                message=(
                    "Endpoint telemetry indicates execution of a "
                    f"suspicious process: {endpoint.process_name}."
                ),
            )
        )

    if suspicious_command:
        evidence.append(
            Evidence(
                code="SUSPICIOUS_COMMAND_LINE",
                message=(
                    "Endpoint telemetry contains a command-line "
                    "pattern associated with suspicious execution."
                ),
            )
        )

    confidence = 0.90

    if suspicious_process and suspicious_command:
        confidence = 0.98

    return DetectorResult(
        event_id=event.event_id,
        detector_id="suspicious_process_execution",
        detected=True,
        attack_type=AttackType.SUSPICIOUS_PROCESS_EXECUTION,
        confidence=confidence,
        severity=Severity.HIGH,
        evidence=tuple(evidence),
        source="rule",
        metadata={
            "rule_version": (
                SUSPICIOUS_PROCESS_EXECUTION_RULE_VERSION
            ),
            "process_name": endpoint.process_name,
            "process_id": endpoint.process_id,
            "parent_process": endpoint.parent_process,
            "executable_path": endpoint.executable_path,
            "command_line": endpoint.command_line,
            "suspicious_process": suspicious_process,
            "suspicious_command": suspicious_command,
        },
        domain=DetectorDomain.ENDPOINT,
    )