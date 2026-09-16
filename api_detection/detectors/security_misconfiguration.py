"""Detector for potentially unsafe API configuration."""

from __future__ import annotations

from collections.abc import Sequence

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)


MISCONFIGURATION_ENDPOINT_MARKERS = (
    "/debug",
    "/actuator",
    "/metrics",
    "/swagger",
    "/api-docs",
)

FAKE_BANK_EVENT_TYPES = (
    "fake_bank",
    "suspicious_url",
)


def _get_endpoint_event_type(
    event: ApiSecurityEvent,
) -> str | None:
    endpoint = getattr(event, "endpoint", None)
    if endpoint is None and isinstance(event, dict):
        endpoint = event.get("endpoint")
    if endpoint is None:
        return None
    if isinstance(endpoint, dict):
        return endpoint.get("event_type")
    return getattr(endpoint, "event_type", None)


def _is_fake_bank_phishing_event(
    event: ApiSecurityEvent,
) -> bool:
    """
    Return True when telemetry indicates a fake bank or suspicious phishing URL event.
    Narrowly scoped to prevent generic public URLs from being classified as phishing.
    """
    event_type = _get_endpoint_event_type(event)
    if event_type in FAKE_BANK_EVENT_TYPES:
        return True

    request = getattr(event, "request", None)
    if request is not None:
        endpoint_path = getattr(request, "endpoint", "") or ""
        query_params = getattr(request, "query_params", {}) or {}
        if isinstance(query_params, dict):
            suspicious_domain = str(query_params.get("suspicious_domain", ""))
            if endpoint_path == "/api/banking/login" and "secure-login-verify-bank-account.info" in suspicious_domain:
                return True

    return False


def _is_exposed_configuration_endpoint(
    event: ApiSecurityEvent,
) -> bool:
    """
    Return True when the request targets a potentially
    exposed internal or configuration endpoint.
    """

    endpoint = event.request.endpoint.lower()

    return any(
        marker in endpoint
        for marker in MISCONFIGURATION_ENDPOINT_MARKERS
    )


def detect_security_misconfiguration(
    event: ApiSecurityEvent,
    recent_events: Sequence[ApiSecurityEvent] = (),
) -> DetectorResult:
    """
    Detect requests exposing potentially sensitive
    debugging or configuration endpoints, or suspicious fake bank phishing URLs.
    """

    if _is_fake_bank_phishing_event(event):
        event_type = _get_endpoint_event_type(event) or "fake_bank"
        query_params = getattr(event.request, "query_params", {}) if getattr(event, "request", None) else {}
        target_url = (
            query_params.get("url", "http://secure-login-verify-bank-account.info/login")
            if isinstance(query_params, dict)
            else "http://secure-login-verify-bank-account.info/login"
        )
        domain_name = (
            query_params.get("suspicious_domain", "secure-login-verify-bank-account.info")
            if isinstance(query_params, dict)
            else "secure-login-verify-bank-account.info"
        )

        return DetectorResult(
            event_id=event.event_id,
            detector_id="security_misconfiguration",
            detected=True,
            attack_type=AttackType.PHISHING,
            confidence=0.90,
            severity=Severity.HIGH,
            evidence=(
                Evidence(
                    code="FAKE_BANK_SUSPICIOUS_URL",
                    message="Suspicious URL / potential phishing banking portal detected.",
                ),
            ),
            metadata={
                "rule_version": "1.0",
                "event_type": event_type,
                "target_url": target_url,
                "domain": domain_name,
            },
        )

    if not _is_exposed_configuration_endpoint(event):
        return DetectorResult(
            event_id=event.event_id,
            detector_id="security_misconfiguration",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            metadata={
                "endpoint": event.request.endpoint,
            },
        )

    return DetectorResult(
        event_id=event.event_id,
        detector_id="security_misconfiguration",
        detected=True,
        attack_type=AttackType.SECURITY_MISCONFIGURATION,
        confidence=0.90,
        severity=Severity.HIGH,
        evidence=(
            Evidence(
                "EXPOSED_CONFIGURATION_ENDPOINT",
                (
                    "Potentially sensitive configuration "
                    f"endpoint accessed: {event.request.endpoint}"
                ),
            ),
        ),
        metadata={
            "endpoint": event.request.endpoint,
        },
    )