try:
    import pytest
except ImportError:
    pytest = None

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database import events_collection

from dataclasses import asdict
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.main import app
from backend.schemas.api_security_event import (
    ApiSecurityEvent,
    EndpointInfo,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResourceInfo,
    ResponseInfo,
)
from backend.schemas.detector_result import DetectionEvidence, DetectorMetadata, DetectorResult
from backend.schemas.impact_assessment import ImpactAssessment
from backend.schemas.risk_assessment import RiskAssessment
from backend.services.event_processor import EventProcessor
from backend.services.detection_service import DetectionService
from backend.services.impact_service import ImpactService
from backend.services.mitigation_service import MitigationService
from api_detection.backend_adapter import adapt_backend_event, run_for_backend
from api_detection.contracts import DetectorDomain
from api_detection.detectors import detect_suspicious_process_execution
from api_detection.simulator import suspicious_process_execution_event


def build_event(event_id: str, search_value: str) -> ApiSecurityEvent:
    return ApiSecurityEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        network=NetworkInfo(
            source_ip="192.168.1.100",
            user_agent="pytest-client",
        ),
        identity=IdentityInfo(
            user_id="test-user",
            session_id="test-session",
            roles=["customer"],
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="GET",
            endpoint="/api/products",
            query_params={"search": search_value},
        ),
        response=ResponseInfo(
            status_code=200,
            latency_ms=50,
        ),
        resource=ResourceInfo(
            resource_type="product",
        ),
    )


CLEANUP_EVENT_IDS = [
    "pytest-sqli-001",
    "pytest-benign-001",
    "pytest-persistence-001",
    "pytest-error-001",
    "evt-suspicious-process-001",
    "pytest-fin-001",
    "pytest-cred-001",
    "pytest-ato-001",
    "pytest-url-001",
    "test-ep-preserve-001",
    "test-net-preserve-001",
]


def do_cleanup():
    for event_id in CLEANUP_EVENT_IDS:
        events_collection.delete_many({"event_id": event_id})


if pytest is not None:
    @pytest.fixture
    def clean_test_events():
        do_cleanup()
        yield
        do_cleanup()
else:
    def clean_test_events():
        do_cleanup()



def test_sql_injection_triggers_block(clean_test_events=None):
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    processor = EventProcessor()

    event = build_event(
        "pytest-sqli-001",
        "UNION SELECT",
    )

    result = processor.process(event)
    
    assert result.source_ip == "192.168.1.100"

    sql_detector = next(
        detector
        for detector in result.detector_results
        if detector.detector_id == "sql_injection"
    )

    assert sql_detector.detected is True
    assert sql_detector.attack_type == "SQL_INJECTION"
    assert sql_detector.confidence == 0.96

    assert result.risk_assessment is not None
    assert result.risk_assessment.risk_score == 80.4
    assert result.risk_assessment.risk_level == "HIGH"
    assert result.risk_assessment.threat_detected is True

    assert result.impact is not None
    assert result.impact.impact_identified is True
    assert "data exposure" in result.impact.categories
    assert result.impact.primary_impact == "data exposure"

    assert result.mitigation_action == "RATE_LIMIT"


def test_benign_event_allows_request(clean_test_events=None):
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    processor = EventProcessor()

    event = build_event(
        "pytest-benign-001",
        "laptop",
    )

    result = processor.process(event)

    assert result.risk_assessment is not None
    assert result.risk_assessment.risk_score == 0.0
    assert result.risk_assessment.risk_level == "LOW"
    assert result.risk_assessment.threat_detected is False

    assert result.impact is not None
    assert result.impact.impact_identified is False
    assert result.impact.categories == []
    assert result.impact.primary_impact is None
    assert result.impact.severity == "LOW"

    assert result.mitigation_action == "ALLOW"




def test_invalid_event_is_rejected():
    client = TestClient(app)

    response = client.post(
        "/events",
        json={
            "event": {
                "event_id": "pytest-invalid-001"
            }
        },
    )

    assert response.status_code == 422



def test_processing_result_is_persisted(clean_test_events=None):
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    processor = EventProcessor()
    event = build_event("pytest-persistence-001", "UNION SELECT")

    result = processor.process(event)

    stored_event = events_collection.find_one(
        {"event_id": event.event_id}
    )

    assert stored_event is not None
    assert "processing" in stored_event
    assert len(stored_event["processing"]["detector_results"]) == 18
    assert stored_event["processing"]["risk_assessment"]["risk_level"] == "HIGH"
    assert "impact" in stored_event["processing"]
    assert stored_event["processing"]["impact"] is not None
    assert stored_event["processing"]["impact"]["impact_identified"] is True
    assert "data exposure" in stored_event["processing"]["impact"]["categories"]
    assert stored_event["processing"]["mitigation_action"] == "RATE_LIMIT"


def test_event_processing_failure_returns_500(monkeypatch=None):
    client = TestClient(app)

    def failing_process(*args, **kwargs):
        raise RuntimeError("Simulated processing failure")

    event = build_event("pytest-error-001", "laptop")

    if monkeypatch is not None:
        monkeypatch.setattr(
            "backend.routes.events.processor.process",
            failing_process,
        )
        response = client.post(
            "/events",
            json={"event": event.model_dump(mode="json")},
        )
        assert response.status_code == 500
        assert response.json() == {"detail": "Event processing failed"}
    else:
        from unittest.mock import patch
        with patch("backend.routes.events.processor.process", side_effect=RuntimeError("Simulated processing failure")):
            response = client.post(
                "/events",
                json={"event": event.model_dump(mode="json")},
            )
            assert response.status_code == 500
            assert response.json() == {"detail": "Event processing failed"}


# ==============================================================
# M3-01 TELEMETRY & ADAPTER INTEGRATION TESTS
# ==============================================================

def test_endpoint_telemetry_preserved_through_adapter():
    """Verify EndpointInfo fields are preserved through the adapter."""
    backend_event = ApiSecurityEvent(
        event_id="test-ep-preserve-001",
        timestamp=datetime.now(timezone.utc),
        domain="ENDPOINT",
        network=NetworkInfo(source_ip="10.0.0.5"),
        identity=IdentityInfo(user_id="user_admin"),
        request=RequestInfo(method="POST", endpoint="/api/endpoint-log"),
        response=ResponseInfo(status_code=200, latency_ms=5.0),
        resource=ResourceInfo(),
        endpoint=EndpointInfo(
            event_type="process_execution",
            hostname="workstation-01",
            username="analyst",
            process_name="powershell.exe",
            process_id=4180,
            parent_process="explorer.exe",
            executable_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -EncodedCommand SYNTHETIC_DEMO",
            privilege_level="user",
            keyboard_hook=False,
            network_connection=False,
            elevated=False,
        ),
    )

    detector_event = adapt_backend_event(backend_event)

    assert detector_event.endpoint is not None
    assert detector_event.endpoint.process_name == "powershell.exe"
    assert detector_event.endpoint.process_id == 4180
    assert detector_event.endpoint.parent_process == "explorer.exe"
    assert detector_event.endpoint.command_line == "powershell.exe -EncodedCommand SYNTHETIC_DEMO"
    assert detector_event.endpoint.hostname == "workstation-01"
    assert detector_event.endpoint.username == "analyst"


def test_network_metrics_preserved_through_adapter():
    """Verify destination_ip, ports, protocol, bytes, and connection_status are preserved."""
    backend_event = ApiSecurityEvent(
        event_id="test-net-preserve-001",
        timestamp=datetime.now(timezone.utc),
        domain="NETWORK",
        network=NetworkInfo(
            source_ip="192.0.2.30",
            user_agent="network-probe/1.0",
            destination_ip="198.51.100.30",
            source_port=54321,
            destination_port=1000,
            protocol="TCP",
            bytes=64,
            packets=1,
            connection_status="rejected",
        ),
        identity=IdentityInfo(),
        request=RequestInfo(method="GET", endpoint="/api/probe"),
        response=ResponseInfo(status_code=403, latency_ms=10.0),
        resource=ResourceInfo(),
    )

    detector_event = adapt_backend_event(backend_event)

    assert detector_event.network.source_ip == "192.0.2.30"
    assert detector_event.network.user_agent == "network-probe/1.0"
    assert detector_event.network.destination_ip == "198.51.100.30"
    assert detector_event.network.source_port == 54321
    assert detector_event.network.destination_port == 1000
    assert detector_event.network.protocol == "TCP"
    assert detector_event.network.bytes == 64
    assert detector_event.network.packets == 1
    assert detector_event.network.connection_status == "rejected"


def test_detector_domain_preserved_in_detector_result():
    """Verify DetectionService returns validated DetectorResult with domain preserved."""
    endpoint_fixture = suspicious_process_execution_event()
    backend_event = ApiSecurityEvent.model_validate(asdict(endpoint_fixture))

    service = DetectionService()
    results = service.detect(backend_event, recent_events=[])

    assert len(results) == 18

    spe = next((r for r in results if r.detector_id == "suspicious_process_execution"), None)
    assert spe is not None
    assert spe.detected is True
    assert spe.domain == "ENDPOINT"

    domains = {r.domain for r in results}
    assert "API" in domains
    assert "NETWORK" in domains
    assert "ENDPOINT" in domains


def test_endpoint_event_triggers_suspicious_process_detection():
    """Verify that adapted endpoint event triggers detect_suspicious_process_execution."""
    endpoint_event = suspicious_process_execution_event()
    adapted = adapt_backend_event(endpoint_event)
    result = detect_suspicious_process_execution(adapted)

    assert result.detected is True
    assert result.detector_id == "suspicious_process_execution"
    assert result.attack_type.value == "SUSPICIOUS_PROCESS_EXECUTION"
    assert result.domain == DetectorDomain.ENDPOINT


def test_post_events_suspicious_process_execution_full_pipeline():
    """
    Verify full end-to-end HTTP pipeline:
    POST /events -> EventProcessor -> DetectionService -> adapter -> detector
    """
    client = TestClient(app)
    endpoint_fixture = suspicious_process_execution_event()
    payload = {"event": asdict(endpoint_fixture)}

    response = client.post("/events", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "processed"
    assert data["event_id"] == endpoint_fixture.event_id

    spe = next((d for d in data["detector_results"] if d["detector_id"] == "suspicious_process_execution"), None)
    assert spe is not None
    assert spe["detected"] is True
    assert spe["attack_type"] == "SUSPICIOUS_PROCESS_EXECUTION"
    assert spe["domain"] == "ENDPOINT"

    risk = data["risk_assessment"]
    assert risk is not None
    assert risk["threat_detected"] is True
    assert "SUSPICIOUS_PROCESS_EXECUTION" in risk["attack_types"]
    assert data["impact"] is not None
    assert data["impact"]["impact_identified"] is True
    assert data["impact"]["primary_impact"] == "endpoint compromise"
    assert "endpoint compromise" in data["impact"]["categories"]
    assert data["mitigation_action"] == "QUARANTINE"


# ==============================================================
# M3-02 IMPACT ENGINE & ADVANCED MITIGATION TESTS
# ==============================================================

def test_credential_compromise_impact_assessment():
    """Verify ImpactService assigns credential compromise for credential attacks."""
    event = build_event("pytest-cred-001", "admin")
    detector_result = DetectorResult(
        event_id=event.event_id,
        detector_id="credential_attack",
        detected=True,
        attack_type="CREDENTIAL_ATTACK",
        confidence=0.95,
        severity="HIGH",
        evidence=[DetectionEvidence(code="CREDENTIAL_STUFFING", message="Stuffing detected")],
        metadata=DetectorMetadata(),
        domain="API",
    )
    risk = RiskAssessment(
        event_id=event.event_id,
        risk_score=75.0,
        risk_level="HIGH",
        threat_detected=True,
        attack_types=["CREDENTIAL_ATTACK"],
    )

    impact_service = ImpactService()
    impact = impact_service.assess(event, detector_results=[detector_result], risk_assessment=risk)

    assert impact.impact_identified is True
    assert "credential compromise" in impact.categories
    assert impact.primary_impact == "credential compromise"
    assert impact.severity == "HIGH"


def test_account_takeover_impact_assessment():
    """Verify ImpactService assigns account takeover for account takeover attacks."""
    event = build_event("pytest-ato-001", "victim")
    detector_result = DetectorResult(
        event_id=event.event_id,
        detector_id="account_takeover",
        detected=True,
        attack_type="ACCOUNT_TAKEOVER",
        confidence=0.92,
        severity="CRITICAL",
        evidence=[DetectionEvidence(code="ACCOUNT_TAKEOVER", message="Account takeover detected")],
        metadata=DetectorMetadata(),
        domain="API",
    )
    risk = RiskAssessment(
        event_id=event.event_id,
        risk_score=92.0,
        risk_level="CRITICAL",
        threat_detected=True,
        attack_types=["ACCOUNT_TAKEOVER"],
    )

    impact_service = ImpactService()
    impact = impact_service.assess(event, detector_results=[detector_result], risk_assessment=risk)

    assert impact.impact_identified is True
    assert "account takeover" in impact.categories
    assert impact.primary_impact == "account takeover"
    assert impact.severity == "CRITICAL"


def test_endpoint_compromise_quarantine_mitigation():
    """Verify MitigationService assigns QUARANTINE for endpoint compromise."""
    mitigation_service = MitigationService()
    impact = ImpactAssessment(
        impact_identified=True,
        categories=["endpoint compromise"],
        primary_impact="endpoint compromise",
        severity="HIGH",
    )
    risk = RiskAssessment(
        event_id="test-ep",
        risk_score=80.0,
        risk_level="HIGH",
        threat_detected=True,
        attack_types=["SUSPICIOUS_PROCESS_EXECUTION"],
    )

    action = mitigation_service.decide_action(risk_assessment=risk, impact_assessment=impact)
    assert action == "QUARANTINE"


def test_financial_loss_transaction_block_mitigation():
    """Verify MitigationService assigns TRANSACTION_BLOCK for financial loss."""
    mitigation_service = MitigationService()
    impact = ImpactAssessment(
        impact_identified=True,
        categories=["financial loss"],
        primary_impact="financial loss",
        severity="HIGH",
    )
    risk = RiskAssessment(
        event_id="test-fin",
        risk_score=80.0,
        risk_level="HIGH",
        threat_detected=True,
        attack_types=["BUSINESS_FLOW_ABUSE"],
    )

    action = mitigation_service.decide_action(risk_assessment=risk, impact_assessment=impact)
    assert action == "TRANSACTION_BLOCK"


def test_url_block_mitigation():
    """Verify MitigationService assigns URL_BLOCK for phishing/suspicious URLs."""
    mitigation_service = MitigationService()
    impact = ImpactAssessment(
        impact_identified=True,
        categories=["malicious url"],
        primary_impact="malicious url",
        severity="HIGH",
    )
    risk = RiskAssessment(
        event_id="test-url",
        risk_score=75.0,
        risk_level="HIGH",
        threat_detected=True,
        reasons=["Suspicious phishing url detected in request query"],
    )

    action = mitigation_service.decide_action(risk_assessment=risk, impact_assessment=impact)
    assert action == "URL_BLOCK"


def test_end_to_end_financial_loss_pipeline(clean_test_events=None):
    """
    Verify full pipeline for financial loss:
    Event on /api/orders/checkout with attack -> primary_impact="financial loss" -> TRANSACTION_BLOCK -> MongoDB
    """
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    processor = EventProcessor()

    event = ApiSecurityEvent(
        event_id="pytest-fin-001",
        timestamp=datetime.now(timezone.utc),
        network=NetworkInfo(
            source_ip="192.168.1.150",
            user_agent="financial-client",
        ),
        identity=IdentityInfo(
            user_id="user-order-1",
            session_id="session-order-1",
            roles=["customer"],
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="POST",
            endpoint="/api/orders/checkout",
            query_params={"discount": "UNION SELECT"},
        ),
        response=ResponseInfo(
            status_code=200,
            latency_ms=45,
        ),
        resource=ResourceInfo(
            resource_type="order",
        ),
    )

    result = processor.process(event)

    assert result.impact is not None
    assert result.impact.impact_identified is True
    assert "financial loss" in result.impact.categories
    assert result.impact.primary_impact == "financial loss"
    assert result.mitigation_action == "TRANSACTION_BLOCK"

    # Verify MongoDB persistence
    stored_event = events_collection.find_one({"event_id": event.event_id})
    assert stored_event is not None
    assert "processing" in stored_event
    assert stored_event["processing"]["impact"]["primary_impact"] == "financial loss"
    assert stored_event["processing"]["mitigation_action"] == "TRANSACTION_BLOCK"


if __name__ == "__main__":
    print("Running backend integration, M3-01 telemetry, and M3-02 impact tests...")
    test_sql_injection_triggers_block()
    print("  test_sql_injection_triggers_block PASSED")
    test_benign_event_allows_request()
    print("  test_benign_event_allows_request PASSED")
    test_invalid_event_is_rejected()
    print("  test_invalid_event_is_rejected PASSED")
    test_processing_result_is_persisted()
    print("  test_processing_result_is_persisted PASSED")
    test_event_processing_failure_returns_500()
    print("  test_event_processing_failure_returns_500 PASSED")
    test_endpoint_telemetry_preserved_through_adapter()
    print("  test_endpoint_telemetry_preserved_through_adapter PASSED")
    test_network_metrics_preserved_through_adapter()
    print("  test_network_metrics_preserved_through_adapter PASSED")
    test_detector_domain_preserved_in_detector_result()
    print("  test_detector_domain_preserved_in_detector_result PASSED")
    test_endpoint_event_triggers_suspicious_process_detection()
    print("  test_endpoint_event_triggers_suspicious_process_detection PASSED")
    test_post_events_suspicious_process_execution_full_pipeline()
    print("  test_post_events_suspicious_process_execution_full_pipeline PASSED")
    test_credential_compromise_impact_assessment()
    print("  test_credential_compromise_impact_assessment PASSED")
    test_account_takeover_impact_assessment()
    print("  test_account_takeover_impact_assessment PASSED")
    test_endpoint_compromise_quarantine_mitigation()
    print("  test_endpoint_compromise_quarantine_mitigation PASSED")
    test_financial_loss_transaction_block_mitigation()
    print("  test_financial_loss_transaction_block_mitigation PASSED")
    test_url_block_mitigation()
    print("  test_url_block_mitigation PASSED")
    test_end_to_end_financial_loss_pipeline()
    print("  test_end_to_end_financial_loss_pipeline PASSED")
    print("\nALL 16 TESTS PASSED SUCCESSFULLY!")