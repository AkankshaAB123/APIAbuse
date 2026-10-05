from backend.schemas.risk_assessment import RiskAssessment
from backend.services.mitigation_service import MitigationService


def test_low_risk_allows_request():
    service = MitigationService()

    assessment = RiskAssessment(
        event_id="test-low",
        risk_score=20,
        risk_level="LOW",
        threat_detected=False,
    )

    assert service.decide_action(assessment) == "ALLOW"


def test_medium_risk_monitors_request():
    service = MitigationService()

    assessment = RiskAssessment(
        event_id="test-medium",
        risk_score=50,
        risk_level="MEDIUM",
        threat_detected=True,
    )

    assert service.decide_action(assessment) == "MONITOR"


def test_high_risk_rate_limits_request():
    service = MitigationService()

    assessment = RiskAssessment(
        event_id="test-high",
        risk_score=80,
        risk_level="HIGH",
        threat_detected=True,
    )

    assert service.decide_action(assessment) == "RATE_LIMIT"


def test_critical_risk_blocks_request():
    service = MitigationService()

    assessment = RiskAssessment(
        event_id="test-critical",
        risk_score=95,
        risk_level="CRITICAL",
        threat_detected=True,
    )

    assert service.decide_action(assessment) == "BLOCK"