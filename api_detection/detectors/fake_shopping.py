"""Detector for deterministic Fake Shopping (Scenario 7) events.

Detects events where the request body explicitly signals a fake shopping
scenario. Returns AttackType.BUSINESS_FLOW_ABUSE with HIGH severity.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)


def _is_fake_shopping_event(event: ApiSecurityEvent) -> bool:
    """Return True if the request body matches the fake‑shopping schema.

    Expected keys (all must be present):
        - scenario == "FAKE_SHOPPING" (case‑insensitive)
        - url
        - social_engineering
        - payment
        - transaction
        - outcome
        - website_status
    """
    body = getattr(event.request, "body", None)
    if not isinstance(body, dict):
        return False

    # Scenario identifier – allow the simulator's lower‑case value as well.
    scenario = str(body.get("scenario", "")).lower()
    if scenario != "fake_shopping":
        return False

    # Validate exact required values
    if body.get("social_engineering") is not True:
        return False
    if body.get("payment") != "completed":
        return False
    if body.get("transaction") != "suspicious":
        return False
    if body.get("outcome") != "product_not_delivered":
        return False
    if body.get("website_status") != "unavailable_after_purchase":
        return False
    if not isinstance(body.get("url"), str) or not body.get("url"):
        return False
    # Additional required keys (domain, product, price)
    required_keys = ["url", "domain", "product", "price"]
    return all(key in body for key in required_keys)


def detect_fake_shopping(
    event: ApiSecurityEvent,
    recent_events: Sequence[ApiSecurityEvent] = (),
) -> DetectorResult:
    """Detect deterministic Fake Shopping activity.

    The detector is deterministic – if the required fields are present it
    reports a detection with confidence 1.0 and severity HIGH.
    """
    if not _is_fake_shopping_event(event):
        return DetectorResult(
            event_id=event.event_id,
            detector_id="fake_shopping",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity=Severity.LOW,
            metadata={},
        )

    body = event.request.body  # type: ignore[arg-type]
    url = body.get("url", "<unknown>")
    evidence_msg = f"Fake shopping scenario detected – URL {url}"
    return DetectorResult(
        event_id=event.event_id,
        detector_id="fake_shopping",
        detected=True,
        attack_type=AttackType.BUSINESS_FLOW_ABUSE,
        confidence=1.0,
        severity=Severity.HIGH,
        evidence=(Evidence("FAKE_SHOPPING_DETECTED", evidence_msg),),
        metadata={"detected_fields": list(body.keys())},
    )
