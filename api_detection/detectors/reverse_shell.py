
from collections.abc import Iterable

from api_detection.contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorDomain,
    DetectorResult,
    Evidence,
    Severity,
)


REVERSE_SHELL_RULE_VERSION = "1.0"


SUSPICIOUS_SHELL_PROCESSES = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
}


def detect_reverse_shell(
    event: ApiSecurityEvent,
    recent_events: Iterable[ApiSecurityEvent] = (),
) -> DetectorResult:
    """
    Detect endpoint telemetry consistent with reverse-shell activity.

    Detection is telemetry-only. This detector does not create,
    execute, or interact with any shell or network connection.
    """
    endpoint = event.endpoint

    if endpoint is None:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="reverse_shell",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": REVERSE_SHELL_RULE_VERSION,
            },
            domain=DetectorDomain.ENDPOINT,
        )

    process_name = (
        endpoint.process_name.lower()
        if endpoint.process_name
        else ""
    )

    parent_process = (
        endpoint.parent_process.lower()
        if endpoint.parent_process
        else ""
    )

    command_line = (
        endpoint.command_line.lower()
        if endpoint.command_line
        else ""
    )

    suspicious_shell = process_name in SUSPICIOUS_SHELL_PROCESSES

    shell_parent = parent_process in SUSPICIOUS_SHELL_PROCESSES

    suspicious_command = any(
        indicator in command_line
        for indicator in (
            "/dev/tcp/",
            "nc ",
            "ncat ",
            "netcat ",
            "socat ",
            "powershell",
            "cmd.exe",
            "bash -i",
        )
    )

    network_connection = endpoint.network_connection is True

    reverse_shell_signal_count = sum(
        (
            suspicious_shell,
            shell_parent,
            suspicious_command,
            network_connection,
        )
    )

    if reverse_shell_signal_count < 2:
        return DetectorResult(
            event_id=event.event_id,
            detector_id="reverse_shell",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            evidence=(),
            source="rule",
            metadata={
                "rule_version": REVERSE_SHELL_RULE_VERSION,
                "process_name": endpoint.process_name,
                "parent_process": endpoint.parent_process,
                "command_line": endpoint.command_line,
                "network_connection": endpoint.network_connection,
                "signal_count": reverse_shell_signal_count,
            },
            domain=DetectorDomain.ENDPOINT,
        )

    evidence = []

    if suspicious_shell:
        evidence.append(
            Evidence(
                code="SHELL_PROCESS",
                message=(
                    "Endpoint telemetry indicates execution of "
                    f"a shell process: {endpoint.process_name}."
                ),
            )
        )

    if shell_parent:
        evidence.append(
            Evidence(
                code="SHELL_PARENT_PROCESS",
                message=(
                    "Endpoint telemetry indicates that the "
                    "process was spawned by a shell process."
                ),
            )
        )

    if suspicious_command:
        evidence.append(
            Evidence(
                code="SUSPICIOUS_SHELL_COMMAND",
                message=(
                    "Endpoint telemetry contains a command-line "
                    "pattern associated with shell-based network "
                    "activity."
                ),
            )
        )

    if network_connection:
        evidence.append(
            Evidence(
                code="SHELL_NETWORK_CONNECTION",
                message=(
                    "Endpoint telemetry indicates that the "
                    "process has an active network connection."
                ),
            )
        )

    confidence = min(
        0.70 + (reverse_shell_signal_count * 0.08),
        0.98,
    )

    return DetectorResult(
        event_id=event.event_id,
        detector_id="reverse_shell",
        detected=True,
        attack_type=AttackType.REVERSE_SHELL,
        confidence=confidence,
        severity=Severity.CRITICAL,
        evidence=tuple(evidence),
        source="rule",
        metadata={
            "rule_version": REVERSE_SHELL_RULE_VERSION,
            "process_name": endpoint.process_name,
            "process_id": endpoint.process_id,
            "parent_process": endpoint.parent_process,
            "executable_path": endpoint.executable_path,
            "command_line": endpoint.command_line,
            "network_connection": endpoint.network_connection,
            "signal_count": reverse_shell_signal_count,
        },
        domain=DetectorDomain.ENDPOINT,
    )
