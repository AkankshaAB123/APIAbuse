"""Single integration entry point for all API-security detectors."""

from __future__ import annotations

from collections.abc import Sequence

from .contracts import ApiSecurityEvent, DetectorResult

from .detectors import detect_account_takeover
from .detectors import detect_bola_idor
from .detectors import detect_broken_function_level_authorization
from .detectors import detect_business_flow_abuse
from .detectors import detect_credential_attacks
from .detectors import detect_endpoint_enumeration
from .detectors import detect_resource_exhaustion
from .detectors import detect_security_misconfiguration
from .detectors import detect_sql_injection
from .detectors import detect_ssrf


def run_all_detectors(
    event: ApiSecurityEvent,
    recent_events: Sequence[ApiSecurityEvent] = (),
) -> list[DetectorResult]:
    """
    Run all registered API-security detectors against
    one event and its relevant history.
    """

    return [
        detect_bola_idor(event, recent_events),

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
    ]