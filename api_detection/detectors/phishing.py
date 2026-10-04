"""Detect controlled phishing telemetry in the existing event pipeline."""

import ipaddress
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

try:
    from ..services.phishing_url_classifier import get_phishing_url_classifier
except Exception:  # pragma: no cover
    get_phishing_url_classifier = None  # type: ignore[assignment]


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

DETERMINISTIC_PHISHING_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "credential",
    "account-update",
    "webscr",
    "banking",
    "ebayisapi",
    "password",
    "authenticate",
    "secure-login",
)

DETERMINISTIC_SUSPICIOUS_TLDS = frozenset({"tk", "ml", "ga", "cf", "gq", "top", "xyz"})


def _normalize_url_indicator(value: str) -> str:
    """Extract an http(s) URL from plain text or Markdown without fetching it."""
    markdown_match = re.search(r"\[[^\]]*\]\((https?://[^)\s]+)\)", value)
    if markdown_match:
        return markdown_match.group(1)

    plain_match = re.search(r"https?://[^\s\]\[)]+", value)
    return plain_match.group(0) if plain_match else value.strip()


def _extract_candidate_url(event: ApiSecurityEvent) -> str:
    """Extract a candidate target URL from event body, query_params, or endpoint."""
    body = event.request.body
    if isinstance(body, dict):
        for key in ("suspicious_url", "url", "phishing_url", "target_url", "link"):
            val = body.get(key)
            if val and isinstance(val, str):
                return _normalize_url_indicator(val)

    if isinstance(event.request.query_params, dict):
        for key in ("url", "suspicious_url", "link", "target", "redirect", "dest"):
            val = event.request.query_params.get(key)
            if val and isinstance(val, str):
                return _normalize_url_indicator(val)

    ep = str(event.request.endpoint or "").strip()
    if ep.startswith(("http://", "https://")) or ("." in ep and "/" in ep and not ep.startswith("/")):
        return _normalize_url_indicator(ep)

    return ""


def _check_deterministic_url_heuristics(url: str) -> list[Evidence]:
    """Evaluate deterministic string-only phishing rules on a candidate URL."""
    evidence: list[Evidence] = []
    if not url:
        return evidence

    norm_url = url if "://" in url else f"http://{url}"
    try:
        parsed = urlparse(norm_url)
        host = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
    except Exception:
        return evidence

    # 1. Simulated login marker
    if host.endswith(".example.test") and any(m in f"{host}{path}" for m in ("login", "verify", "secure", "signin")):
        evidence.append(
            Evidence(
                code="PHISHING_SIMULATED_LOGIN_URL",
                message="Target URL points to a reserved .example.test destination with login or verification marker.",
            )
        )

    # 2. Phishing keyword in path / query
    kw_hits = [kw for kw in DETERMINISTIC_PHISHING_KEYWORDS if kw in f"{path}?{query}"]
    if kw_hits:
        evidence.append(
            Evidence(
                code="PHISHING_HEURISTIC_LOGIN_KEYWORD",
                message=f"URL path or query contains sensitive credential/authentication keyword: {', '.join(kw_hits[:3])}.",
            )
        )

    # 3. Suspicious TLD
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in DETERMINISTIC_SUSPICIOUS_TLDS:
        evidence.append(
            Evidence(
                code="PHISHING_HEURISTIC_SUSPICIOUS_TLD",
                message=f"URL uses high-abuse top-level domain '.{tld}'.",
            )
        )

    # 4. Raw IP host with non-root path
    try:
        ipaddress.ip_address(host.strip("[]"))
        if len(path) > 1:
            evidence.append(
                Evidence(
                    code="PHISHING_HEURISTIC_IP_HOST",
                    message=f"URL uses raw IP address host '{host}' with credential path.",
                )
            )
    except ValueError:
        pass

    return evidence


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
    """Flag controlled phishing lab, synthetic emails, and evaluate URL ML signal under gated policy."""
    del recent_events

    body: Any = event.request.body

    # -------------------------------------------------------------------------
    # 1. Controlled Local Phishing Login Lab
    # -------------------------------------------------------------------------
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
                    message="Dummy credentials were submitted to the controlled local phishing login page.",
                ),
            ),
            source="api_detector",
            metadata={
                "rule_version": PHISHING_RULE_VERSION,
                "window_seconds": 0,
                "domain": DetectorDomain.ENDPOINT.value,
                "model_version": "v3",
                "ml_contributed_to_risk": False,
                "deterministic_rules_fired": True,
                "gated_decision": "DETERMINISTIC_LAB",
            },
            domain=DetectorDomain.ENDPOINT,
        )

    # -------------------------------------------------------------------------
    # 2. Live Synthetic Phishing Email Endpoint
    # -------------------------------------------------------------------------
    is_synthetic_email = (
        event.request.endpoint == EMAIL_PHISHING_ENDPOINT
        and isinstance(body, dict)
        and body.get("event_type") == "synthetic_phishing_email"
    )
    if is_synthetic_email:
        evidence, indicators = _email_indicators(body)
        raw_suspicious_url = str(body.get("suspicious_url", "")).strip()
        candidate_url = _normalize_url_indicator(raw_suspicious_url)

        # Query v3 Phishing URL Classifier
        ml_prob: float | None = None
        if candidate_url and get_phishing_url_classifier is not None:
            try:
                ml_pred = get_phishing_url_classifier().predict(candidate_url)
                ml_prob = ml_pred.get("probability")
            except Exception:
                ml_prob = None

        deterministic_rules_fired = (
            indicators["simulated_login_url"]
            and bool(indicators["social_engineering_terms"])
            and sum(
                (
                    bool(indicators["social_engineering_terms"]),
                    indicators["url_embedded"],
                    indicators["suspicious_sender"],
                )
            )
            >= 2
        )

        if deterministic_rules_fired:
            ev_list = list(evidence)
            ml_contributed = False
            confidence = 0.92

            if ml_prob is not None and ml_prob >= 0.95:
                ev_list.append(
                    Evidence(
                        code="PHISHING_ML_CONFIRMED",
                        message=f"v3 Random Forest classifier confirmed phishing with probability {ml_prob:.4f} (>= 0.95 threshold).",
                    )
                )
                ml_contributed = True

            return DetectorResult(
                event_id=event.event_id,
                detector_id=DETECTOR_ID,
                detected=True,
                attack_type=AttackType.PHISHING,
                confidence=confidence,
                severity=Severity.HIGH,
                evidence=tuple(ev_list),
                source="api_detector",
                metadata={
                    "rule_version": PHISHING_RULE_VERSION,
                    "window_seconds": 0,
                    "domain": DetectorDomain.ENDPOINT.value,
                    "indicators": indicators,
                    "model_version": "v3",
                    "phishing_ml_probability": ml_prob,
                    "ml_contributed_to_risk": ml_contributed,
                    "deterministic_rules_fired": True,
                    "gated_decision": "CONFIRMED_GATED_PHISHING" if ml_contributed else "DETERMINISTIC_ONLY_PHISHING",
                    "url": candidate_url,
                },
                domain=DetectorDomain.ENDPOINT,
            )

        # Deterministic email rules did not fire: evaluate ML score under safety rule
        if ml_prob is not None and ml_prob >= 0.95:
            # CRITICAL SAFETY RULE: High ML alone must NOT directly declare detection or URL_BLOCK
            return DetectorResult(
                event_id=event.event_id,
                detector_id=DETECTOR_ID,
                detected=False,
                attack_type=None,
                confidence=0.0,
                severity=Severity.MEDIUM,
                evidence=(
                    Evidence(
                        code="PHISHING_ML_AUXILIARY_SUSPICION",
                        message=f"v3 Random Forest classifier flagged high probability {ml_prob:.4f} without corroborating deterministic rule; flagged for auxiliary monitoring.",
                    ),
                ),
                source="api_detector",
                metadata={
                    "rule_version": PHISHING_RULE_VERSION,
                    "window_seconds": 0,
                    "domain": DetectorDomain.ENDPOINT.value,
                    "indicators": indicators,
                    "model_version": "v3",
                    "phishing_ml_probability": ml_prob,
                    "ml_contributed_to_risk": True,
                    "deterministic_rules_fired": False,
                    "gated_decision": "SUSPICIOUS_ML_AUXILIARY_ONLY",
                    "auxiliary_suspicion": True,
                    "url": candidate_url,
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
                "indicators": indicators,
                "model_version": "v3",
                "phishing_ml_probability": ml_prob,
                "ml_contributed_to_risk": False,
                "deterministic_rules_fired": False,
                "gated_decision": "BENIGN_OR_CLEAN",
                "url": candidate_url,
            },
            domain=DetectorDomain.ENDPOINT,
        )

    # -------------------------------------------------------------------------
    # 3. General Target URL / Browser Navigation / Security Check
    # -------------------------------------------------------------------------
    candidate_url = _extract_candidate_url(event)
    if candidate_url:
        heuristic_evidence = _check_deterministic_url_heuristics(candidate_url)
        ml_prob = None
        if get_phishing_url_classifier is not None:
            try:
                ml_pred = get_phishing_url_classifier().predict(candidate_url)
                ml_prob = ml_pred.get("probability")
            except Exception:
                ml_prob = None

        # Gated Rule 1: Deterministic heuristic hit + ML probability >= 0.95
        if heuristic_evidence and ml_prob is not None and ml_prob >= 0.95:
            ev_list = list(heuristic_evidence)
            ev_list.append(
                Evidence(
                    code="PHISHING_ML_CONFIRMED",
                    message=f"v3 Random Forest classifier confirmed phishing with probability {ml_prob:.4f} (>= 0.95 threshold).",
                )
            )
            return DetectorResult(
                event_id=event.event_id,
                detector_id=DETECTOR_ID,
                detected=True,
                attack_type=AttackType.PHISHING,
                confidence=round(max(0.92, ml_prob), 2),
                severity=Severity.HIGH,
                evidence=tuple(ev_list),
                source="api_detector",
                metadata={
                    "rule_version": PHISHING_RULE_VERSION,
                    "window_seconds": 0,
                    "domain": DetectorDomain.ENDPOINT.value,
                    "model_version": "v3",
                    "phishing_ml_probability": ml_prob,
                    "ml_contributed_to_risk": True,
                    "deterministic_rules_fired": True,
                    "gated_decision": "CONFIRMED_GATED_PHISHING",
                    "url": candidate_url,
                },
                domain=DetectorDomain.ENDPOINT,
            )

        # Gated Rule 2: Strong deterministic heuristic hit (e.g. simulated login destination or multiple indicators)
        simulated_login_hit = any(e.code == "PHISHING_SIMULATED_LOGIN_URL" for e in heuristic_evidence)
        if simulated_login_hit or len(heuristic_evidence) >= 2:
            return DetectorResult(
                event_id=event.event_id,
                detector_id=DETECTOR_ID,
                detected=True,
                attack_type=AttackType.PHISHING,
                confidence=0.90,
                severity=Severity.HIGH,
                evidence=tuple(heuristic_evidence),
                source="api_detector",
                metadata={
                    "rule_version": PHISHING_RULE_VERSION,
                    "window_seconds": 0,
                    "domain": DetectorDomain.ENDPOINT.value,
                    "model_version": "v3",
                    "phishing_ml_probability": ml_prob,
                    "ml_contributed_to_risk": False,
                    "deterministic_rules_fired": True,
                    "gated_decision": "DETERMINISTIC_ONLY_PHISHING",
                    "url": candidate_url,
                },
                domain=DetectorDomain.ENDPOINT,
            )

        # Gated Rule 3: High ML score alone (>= 0.95) without deterministic rule
        # CRITICAL SAFETY RULE: High ML alone must NOT directly cause URL_BLOCK
        if ml_prob is not None and ml_prob >= 0.95:
            return DetectorResult(
                event_id=event.event_id,
                detector_id=DETECTOR_ID,
                detected=False,
                attack_type=None,
                confidence=0.0,
                severity=Severity.MEDIUM,
                evidence=(
                    Evidence(
                        code="PHISHING_ML_AUXILIARY_SUSPICION",
                        message=f"v3 Random Forest classifier flagged high probability {ml_prob:.4f} without corroborating deterministic rule; flagged for auxiliary monitoring.",
                    ),
                ),
                source="api_detector",
                metadata={
                    "rule_version": PHISHING_RULE_VERSION,
                    "window_seconds": 0,
                    "domain": DetectorDomain.ENDPOINT.value,
                    "model_version": "v3",
                    "phishing_ml_probability": ml_prob,
                    "ml_contributed_to_risk": True,
                    "deterministic_rules_fired": False,
                    "gated_decision": "SUSPICIOUS_ML_AUXILIARY_ONLY",
                    "auxiliary_suspicion": True,
                    "url": candidate_url,
                },
                domain=DetectorDomain.ENDPOINT,
            )

        # Clean / Benign URL
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
                "model_version": "v3",
                "phishing_ml_probability": ml_prob,
                "ml_contributed_to_risk": False,
                "deterministic_rules_fired": False,
                "gated_decision": "BENIGN_OR_CLEAN",
                "url": candidate_url,
            },
            domain=DetectorDomain.ENDPOINT,
        )

    # -------------------------------------------------------------------------
    # 4. Default Clean Result (No Target URL and No Lab Match)
    # -------------------------------------------------------------------------
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
            "model_version": "v3",
            "ml_contributed_to_risk": False,
            "deterministic_rules_fired": False,
            "gated_decision": "NO_URL_PRESENT",
        },
        domain=DetectorDomain.ENDPOINT,
    )

