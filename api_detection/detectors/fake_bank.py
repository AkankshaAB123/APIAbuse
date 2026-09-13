from __future__ import annotations

from typing import Sequence

from ..contracts import (
    ApiSecurityEvent,
    DetectorResult,
    AttackType,
    Severity,
    Evidence,
)

def _is_fake_bank_event(event: ApiSecurityEvent) -> bool:
    """Return True if the event matches the exact Fake Bank contract.

    Checks that required fields exist and have the exact expected values.
    """
    body = event.request.body
    if not isinstance(body, dict):
        return False
    required = {
        "scenario": "FAKE_BANK",
        "brand_impersonation": True,
        "login_language": True,
        "verification_language": True,
        "user_action": "clicked_link",
        "url_structure": "suspicious",
    }
    for key, val in required.items():
        if body.get(key) != val:
            return False
    if not isinstance(body.get("url"), str) or not body.get("url"):
        return False
    if not isinstance(body.get("domain"), str) or not body.get("domain"):
        return False
    if not isinstance(body.get("brand"), str) or not body.get("brand"):
        return False
    if str(body.get("scenario")).upper() != "FAKE_BANK":
        return False
    return True

def detect_fake_bank(event: ApiSecurityEvent, recent_events: Sequence[ApiSecurityEvent] = ()) -> DetectorResult:
    """Detect Fake Bank phishing scenario.

    Returns a DetectorResult with AttackType.PHISHING when all required contract fields match.
    """
    if _is_fake_bank_event(event):
        return DetectorResult(
            event_id=event.event_id,
            detector_id="fake_bank",
            detected=True,
            attack_type=AttackType.PHISHING,
            confidence=1.0,
            severity=Severity.HIGH,
            evidence=(
                Evidence(
                    code="FAKE_BANK_SUSPICIOUS_URL",
                    message="Suspicious URL / potential phishing",
                ),
            ),
            metadata={"matched_fields": list(event.request.body.keys())},
        )
    return DetectorResult(
        event_id=event.event_id,
        detector_id="fake_bank",
        detected=False,
        attack_type=None,
        confidence=0.0,
        severity=Severity.LOW,
        evidence=(),
        metadata={},
    )
