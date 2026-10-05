import pytest
from api_detection.contracts import ApiSecurityEvent, AttackType, RequestInfo, NetworkInfo, IdentityInfo
from api_detection.detectors.xss import detect_xss

def create_event(payload) -> ApiSecurityEvent:
    return ApiSecurityEvent(
        event_id="test_xss_1",
        timestamp="2026-01-01T00:00:00Z",
        network=NetworkInfo(source_ip="127.0.0.1"),
        identity=IdentityInfo(user_id="test_user"),
        request=RequestInfo(
            method="GET",
            endpoint="/search",
            query_params={"q": payload}
        ),
        response=None,
    )

def test_dynamic_detection_xss_script_tag():
    event = create_event("<script>alert(1)</script>")
    result = detect_xss(event)
    assert result.detected is True
    assert result.attack_type == AttackType.XSS
    assert any("SCRIPT_TAG" in e.code for e in result.evidence)

def test_dynamic_detection_xss_event_handler():
    event = create_event("<img src=x onerror=alert(1)>")
    result = detect_xss(event)
    assert result.detected is True
    assert result.attack_type == AttackType.XSS
    assert any("EVENT_HANDLER" in e.code for e in result.evidence)

def test_benign_input():
    event = create_event("normal search query")
    result = detect_xss(event)
    assert result.detected is False
    assert result.attack_type is None
    assert len(result.evidence) == 0

def test_no_attack_label_needed():
    # The payload detection works entirely on the input content,
    # without needing any "attack_type" property in the request.
    event = create_event("javascript:alert(1)")
    result = detect_xss(event)
    assert result.detected is True
    assert result.attack_type == AttackType.XSS
    assert any("JAVASCRIPT_PROTOCOL" in e.code for e in result.evidence)
