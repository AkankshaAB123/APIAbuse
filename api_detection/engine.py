"""Single integration entry point for all API-security detectors."""

from __future__ import annotations

from collections.abc import Sequence

from .contracts import ApiSecurityEvent, DetectorResult

from api_detection.detectors import (
    detect_account_takeover,
    detect_bola_idor,
    detect_broken_function_level_authorization,
    detect_business_flow_abuse,
    detect_credential_attacks,
    detect_ddos,
    detect_dos_flooding,
    detect_endpoint_enumeration,
    detect_keylogging,
    detect_network_brute_force,
    detect_port_scanning,
    detect_privilege_escalation,
    detect_resource_exhaustion,
    detect_reverse_shell,
    detect_security_misconfiguration,
    detect_sql_injection,
    detect_ssrf,
    detect_suspicious_process_execution,
)


def run_all_detectors(
    event: ApiSecurityEvent,
    recent_events: Sequence[ApiSecurityEvent] = (),
) -> list[DetectorResult]:
    """
    Run all registered API-security detectors against
    one event and its relevant history.
    """

    return [
        # --------------------------------------------------
        # API detectors
        # --------------------------------------------------

        detect_bola_idor(
            event,
            recent_events,
        ),

        detect_broken_function_level_authorization(
            event,
            recent_events,
        ),

        detect_credential_attacks(
            event,
            recent_events,
        ),

        detect_account_takeover(
            event,
            recent_events,
        ),

        detect_sql_injection(
            event,
            recent_events,
        ),

        detect_ssrf(
            event,
            recent_events,
        ),

        detect_resource_exhaustion(
            event,
            recent_events,
        ),

        detect_business_flow_abuse(
            event,
            recent_events,
        ),

        detect_endpoint_enumeration(
            event,
            recent_events,
        ),

        detect_security_misconfiguration(
            event,
            recent_events,
        ),

        # --------------------------------------------------
        # Network detectors
        # --------------------------------------------------

        detect_ddos(
            event,
            recent_events,
        ),

        detect_dos_flooding(
            event,
            recent_events,
        ),

        detect_port_scanning(
            event,
            recent_events,
        ),

        detect_network_brute_force(
            event,
            recent_events,
        ),

        # --------------------------------------------------
        # Endpoint detectors
        # --------------------------------------------------

        detect_keylogging(
            event,
            recent_events,
        ),

        detect_suspicious_process_execution(
            event,
            recent_events,
        ),

        detect_reverse_shell(
            event,
            recent_events,
        ),

        detect_privilege_escalation(
            event,
            recent_events,
        ),
    ]