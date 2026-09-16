"""Detect controlled phishing telemetry in the existing event pipeline."""

from collections.abc import Sequence
import re
from typing import Any
from urllib.parse import urlparse

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorDomain,
    DetectorResult,
    Evidence,
    Severity,
)


DETECTOR_ID = "phishing"
PHISHING_RULE_VERSION = "1.0"
EMAIL_PHISHING_ENDPOINT = "/lab/phishing/email"

SOCIAL_ENGINEERING_TERMS = (
    "verify",
    "verification",
    "urgent",
    "immediately",
    "suspended",
    "security alert",
    "account",
    "password",
    "login",
    "sign in",
    "credential",
)

LINK_REFERENCE_TERMS = (
    "link below",
    "click here",
    "using the link",
    "follow this link",
)


def _normalize_url_indicator(value: str) -> str:
    """Extract an http(s) URL from plain text or Markdown without fetching it."""
    markdown_match = re.search(r"\[[^\]]*\]\((https?://[^)\s]+)\)", value)
    if markdown_match:
        return markdown_match.group(1)

    plain_match = re.search(r"https?://[^\s\]\[)]+", value)
    return plain_match.group(0) if plain_match else value.strip()


def _email_indicators(body: dict[str, Any]) -> tuple[list[Evidence], dict[str, Any]]:
    """Return deterministic indicators for a safe synthetic email payload."""
    subject = str(body.get("subject", ""))
    email_body = str(body.get("email_body", ""))
    raw_suspicious_url = str(body.get("suspicious_url", "")).strip()
    suspicious_url = _normalize_url_indicator(raw_suspicious_url)
    sender = str(body.get("sender", "")).strip().lower()
    sender_local, _, sender_domain = sender.partition("@")
    parsed_url = urlparse(suspicious_url)
    host = (parsed_url.hostname or "").lower()
    path = parsed_url.path.lower()
    message_text = f"{subject} {email_body}".lower()

    social_terms = [term for term in SOCIAL_ENGINEERING_TERMS if term in message_text]
    simulated_login_url = (
        parsed_url.scheme in {"http", "https"}
        and host.endswith(".example.test")
        and any(marker in f"{host}{path}" for marker in ("login", "verify", "secure", "signin"))
    )
    url_embedded = bool(suspicious_url) and (
        suspicious_url in email_body
        or raw_suspicious_url in email_body
        or any(term in message_text for term in LINK_REFERENCE_TERMS)
    )
    suspicious_sender = (
        sender_domain.endswith(".example.test")
        and any(marker in sender_local for marker in ("security", "alert", "login", "verify"))
    )

    evidence: list[Evidence] = []
    if social_terms:
        evidence.append(
            Evidence(
                code="PHISHING_SOCIAL_ENGINEERING_LANGUAGE",
                message=(
                    "Synthetic email contains account or credential verification "
                    f"language: {', '.join(social_terms[:4])}."
                ),
            )
        )
    if simulated_login_url:
        evidence.append(
            Evidence(
                code="PHISHING_SIMULATED_LOGIN_URL",
                message=(
                    "Synthetic email points to a reserved .example.test URL with "
                    "a login or verification-style destination."
                ),
            )
        )
    if suspicious_sender:
        evidence.append(
            Evidence(
                code="PHISHING_SIMULATED_SENDER_DOMAIN",
                message=(
                    "Synthetic sender uses a reserved .example.test domain with "
                    "a security or login-themed sender identity."
                ),
            )
        )
    if url_embedded:
        evidence.append(
            Evidence(
                code="PHISHING_URL_EMBEDDED_IN_MESSAGE",
                message=(
                    "The submitted synthetic email references the supplied URL "
                    "through an embedded URL or link-invitation language."
                ),
            )
        )

    return evidence, {
        "social_engineering_terms": social_terms,
        "simulated_login_url": simulated_login_url,
        "suspicious_sender": suspicious_sender,
        "url_embedded": url_embedded,
        "url_host": host or None,
    }


def detect_phishing(
    event: ApiSecurityEvent,
    recent_events: Sequence[ApiSecurityEvent] = (),
) -> DetectorResult:
    """Flag the controlled login lab and live synthetic phishing emails."""
    del recent_events

    body: Any = event.request.body
    is_body_match = (
        isinstance(body, dict)
        and body.get("credential_submission_observed") is True
        and body.get("credential_capture_observed") is True
        and body.get("phishing_url") == "/lab/phishing/login"
    )

    if event.request.endpoint == "/lab/phishing/login" and is_body_match:
        return DetectorResult(
            event_id=event.event_id,
            detector_id=DETECTOR_ID,
            detected=True,
            attack_type=AttackType.PHISHING,
            confidence=0.94,
            severity=Severity.HIGH,
            evidence=(
                Evidence(
                    code="CONTROLLED_CREDENTIAL_CAPTURE",
                    message=(
                        "Dummy credentials were submitted to the controlled "
                        "local phishing login page."
                    ),
                ),
            ),
            source="api_detector",
            metadata={
                "rule_version": PHISHING_RULE_VERSION,
                "window_seconds": 0,
                "domain": DetectorDomain.ENDPOINT.value,
            },
            domain=DetectorDomain.ENDPOINT,
        )

    is_synthetic_email = (
        event.request.endpoint == EMAIL_PHISHING_ENDPOINT
        and isinstance(body, dict)
        and body.get("event_type") == "synthetic_phishing_email"
    )
    if is_synthetic_email:
        evidence, indicators = _email_indicators(body)
        # Require multiple independent signals. The URL remains a string-only
        # indicator; it is never contacted or fetched by the detector.
        if (
            indicators["simulated_login_url"]
            and bool(indicators["social_engineering_terms"])
            and sum(
                (
                    bool(indicators["social_engineering_terms"]),
                    indicators["url_embedded"],
                    indicators["suspicious_sender"],
                )
            ) >= 2
        ):
            return DetectorResult(
                event_id=event.event_id,
                detector_id=DETECTOR_ID,
                detected=True,
                attack_type=AttackType.PHISHING,
                confidence=0.92,
                severity=Severity.HIGH,
                evidence=tuple(evidence),
                source="api_detector",
                metadata={
                    "rule_version": PHISHING_RULE_VERSION,
                    "window_seconds": 0,
                    "domain": DetectorDomain.ENDPOINT.value,
                    "indicators": indicators,
                },
                domain=DetectorDomain.ENDPOINT,
            )

    return DetectorResult(
        event_id=event.event_id,
        detector_id=DETECTOR_ID,
        detected=False,
        attack_type=None,
        confidence=0.0,
        severity=Severity.LOW,
        evidence=(),
        source="api_detector",
        metadata={
            "rule_version": PHISHING_RULE_VERSION,
            "window_seconds": 0,
            "domain": DetectorDomain.ENDPOINT.value,
        },
        domain=DetectorDomain.ENDPOINT,
    )
