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
from unittest.mock import patch
from backend.schemas.detector_result import DetectionEvidence, DetectorMetadata, DetectorResult
from backend.schemas.impact_assessment import ImpactAssessment
from backend.schemas.ml_result import AnomalyDetectionResult, MLDetectionResult, MLResult
from backend.schemas.risk_assessment import RiskAssessment
from backend.services.event_processor import EventProcessor
from backend.services.detection_service import DetectionService
from backend.services.impact_service import ImpactService
from backend.services.mitigation_service import MitigationService
from backend.services.auth_service import create_access_token
from api_detection.backend_adapter import adapt_backend_event, run_for_backend
from api_detection.contracts import DetectorDomain
from api_detection.detectors import detect_suspicious_process_execution
from api_detection.simulator import suspicious_process_execution_event


def get_auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': 'admin', 'role': 'ADMIN'})}"}


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
    "pytest-ml-fail-001",
    "pytest-db-fail-001",
    "pytest-laptop-agent-001",
    "pytest-mobile-agent-001",
    "pytest-ml-anomaly-001",
    "pytest-direct-ingest-001",
    "pytest-wrapped-ingest-001",
    "pytest-direct-threat-001",
    "pytest-threats-impact-001",
    "pytest-threats-endpoint-001",
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
    assert len(stored_event["processing"]["detector_results"]) == 22
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

    assert len(results) == 22

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


# ==============================================================
# M3-03 PIPELINE HARDENING & RESILIENCE TESTS
# ==============================================================

def test_ml_failure_resilience_in_pipeline(clean_test_events=None):
    """Verify that a failure during ML inference does not crash POST /events."""
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    client = TestClient(app)
    event = build_event("pytest-ml-fail-001", "laptop")
    payload = {
        "event": event.model_dump(mode="json"),
        "ml_features": {"Destination Port": 80, "Flow Duration": 1000},
    }

    with patch("backend.services.ml_service.MLService.detect", side_effect=RuntimeError("ML engine offline")):
        response = client.post("/events", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "processed"
    assert data["ml_result"] is None
    assert len(data["detector_results"]) == 22
    assert data["risk_assessment"] is not None
    assert data["mitigation_action"] == "ALLOW"


def test_recent_events_db_failure_resilience(clean_test_events=None):
    """Verify that a database error during recent-events query falls back to empty history and continues."""
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    processor = EventProcessor()
    event = build_event("pytest-db-fail-001", "laptop")

    with patch.object(processor.repository, "get_recent_events", side_effect=Exception("MongoDB timeout")):
        result = processor.process(event)

    assert result.status == "processed"
    assert len(result.detector_results) == 22
    assert result.risk_assessment is not None
    assert result.mitigation_action == "ALLOW"


def test_laptop_endpoint_telemetry_pipeline_and_persistence(clean_test_events=None):
    """Verify Laptop Agent telemetry travels through POST /events, triggers quarantine, and is preserved in MongoDB."""
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    client = TestClient(app)

    laptop_event = ApiSecurityEvent(
        event_id="pytest-laptop-agent-001",
        timestamp=datetime.now(timezone.utc),
        domain="ENDPOINT",
        network=NetworkInfo(source_ip="10.10.4.22", user_agent="LaptopAgent/1.0"),
        identity=IdentityInfo(user_id="analyst_alice", roles=["security_analyst"], is_authenticated=True),
        request=RequestInfo(method="POST", endpoint="/api/endpoint-telemetry"),
        response=ResponseInfo(status_code=200, latency_ms=12.0),
        resource=ResourceInfo(resource_type="endpoint"),
        endpoint=EndpointInfo(
            event_type="suspicious_process_execution",
            hostname="laptop-alice-x1",
            username="alice",
            process_name="powershell.exe",
            process_id=8192,
            parent_process="cmd.exe",
            executable_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -EncodedCommand SYNTHETIC_DEMO",
            privilege_level="user",
            keyboard_hook=False,
            network_connection=True,
            elevated=False,
        ),
    )

    response = client.post("/events", json={"event": laptop_event.model_dump(mode="json")})
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "processed"
    assert data["impact"]["primary_impact"] == "endpoint compromise"
    assert data["mitigation_action"] == "QUARANTINE"

    # Verify MongoDB raw event persistence preserved all endpoint fields
    stored_event = events_collection.find_one({"event_id": "pytest-laptop-agent-001"})
    assert stored_event is not None
    assert stored_event["endpoint"]["hostname"] == "laptop-alice-x1"
    assert stored_event["endpoint"]["process_name"] == "powershell.exe"
    assert stored_event["endpoint"]["command_line"] == "powershell.exe -EncodedCommand SYNTHETIC_DEMO"
    assert stored_event["endpoint"]["process_id"] == 8192
    assert stored_event["processing"]["mitigation_action"] == "QUARANTINE"


def test_mobile_network_telemetry_pipeline_and_persistence(clean_test_events=None):
    """Verify Mobile Agent network telemetry travels through POST /events and persists completely."""
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    client = TestClient(app)

    mobile_event = ApiSecurityEvent(
        event_id="pytest-mobile-agent-001",
        timestamp=datetime.now(timezone.utc),
        domain="NETWORK",
        network=NetworkInfo(
            source_ip="172.16.0.45",
            user_agent="Dalvik/2.1.0 (Android 14; MobileAgent/2.0)",
            destination_ip="198.51.100.80",
            source_port=48210,
            destination_port=443,
            protocol="TCP",
            bytes=2048,
            packets=16,
            connection_status="established",
        ),
        identity=IdentityInfo(user_id="mobile_user_99", is_authenticated=True),
        request=RequestInfo(method="GET", endpoint="/api/mobile/feed"),
        response=ResponseInfo(status_code=200, latency_ms=30.0),
        resource=ResourceInfo(resource_type="feed"),
    )

    response = client.post("/events", json={"event": mobile_event.model_dump(mode="json")})
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "processed"

    # Verify MongoDB persistence of full network metrics
    stored_event = events_collection.find_one({"event_id": "pytest-mobile-agent-001"})
    assert stored_event is not None
    assert stored_event["network"]["destination_ip"] == "198.51.100.80"
    assert stored_event["network"]["source_port"] == 48210
    assert stored_event["network"]["destination_port"] == 443
    assert stored_event["network"]["protocol"] == "TCP"
    assert stored_event["network"]["bytes"] == 2048
    assert stored_event["network"]["packets"] == 16
    assert stored_event["network"]["connection_status"] == "established"


def test_ml_only_threat_anomaly_impact_classification():
    """Verify ImpactService produces appropriate fallback impact for ML-only threat/anomaly."""
    event = build_event("pytest-ml-anomaly-001", "normal")
    ml_result = MLResult(
        detection=MLDetectionResult(
            prediction="DDoS",
            confidence=0.96,
            attack_explanation={"summary": "Volumetric flow anomaly"},
            reasons=[],
            model="xgboost",
        ),
        anomaly=AnomalyDetectionResult(
            is_anomaly=True,
            anomaly_score=-0.45,
        ),
    )

    impact_service = ImpactService()
    impact = impact_service.assess(event=event, detector_results=[], risk_assessment=None, ml_result=ml_result)

    assert impact.impact_identified is True
    assert impact.primary_impact == "service disruption"
    assert "service disruption" in impact.categories


def test_ml_only_benign_produces_no_impact():
    """Verify that a benign ML result with no rule detections produces no impact."""
    event = build_event("pytest-ml-benign-001", "normal")
    ml_result = MLResult(
        detection=MLDetectionResult(
            prediction="BENIGN",
            confidence=0.99,
            attack_explanation={},
            reasons=[],
            model="xgboost",
        ),
        anomaly=AnomalyDetectionResult(
            is_anomaly=False,
            anomaly_score=0.35,
        ),
    )

    impact_service = ImpactService()
    impact = impact_service.assess(event=event, detector_results=[], risk_assessment=None, ml_result=ml_result)

    assert impact.impact_identified is False
    assert impact.primary_impact is None
    assert impact.categories == []


def test_post_events_accepts_wrapped_payload(clean_test_events=None):
    """Verify POST /events continues to accept the wrapped EventProcessingRequest format."""
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    client = TestClient(app)
    event = build_event("pytest-wrapped-ingest-001", "normal-product")

    response = client.post(
        "/events",
        json={"event": event.model_dump(mode="json"), "ml_features": None},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "processed"
    assert data["event_id"] == "pytest-wrapped-ingest-001"
    assert data["mitigation_action"] == "ALLOW"


def test_post_events_accepts_direct_raw_event(clean_test_events=None):
    """Verify POST /events accepts a direct raw ApiSecurityEvent payload without wrapping."""
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    client = TestClient(app)
    event = build_event("pytest-direct-ingest-001", "normal-product")

    response = client.post(
        "/events",
        json=event.model_dump(mode="json"),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "processed"
    assert data["event_id"] == "pytest-direct-ingest-001"
    assert data["mitigation_action"] == "ALLOW"


def test_direct_raw_event_triggers_full_processing_pipeline(clean_test_events=None):
    """Verify direct raw ApiSecurityEvent executes the full detection, risk, impact, and mitigation pipeline."""
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    client = TestClient(app)
    event = build_event("pytest-direct-threat-001", "UNION SELECT")

    response = client.post(
        "/events",
        json=event.model_dump(mode="json"),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "processed"
    assert data["event_id"] == "pytest-direct-threat-001"
    assert data["mitigation_action"] == "RATE_LIMIT"
    assert data["risk_assessment"]["threat_detected"] is True
    assert data["impact"]["impact_identified"] is True
    assert "data exposure" in data["impact"]["categories"]


def test_direct_invalid_event_returns_422():
    """Verify an invalid raw event payload is rejected with 422 Unprocessable Entity."""
    client = TestClient(app)
    response = client.post(
        "/events",
        json={"event_id": "malformed-event", "some_key": 123},
    )

    assert response.status_code == 422


def test_get_threats_exposes_persisted_impact_assessment(clean_test_events=None):
    """Verify that GET /threats returns persisted threats with their impact assessment."""
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    client = TestClient(app)
    event = build_event("pytest-threats-impact-001", "UNION SELECT * FROM users")

    # Ingest event so it is processed, assessed, and persisted
    post_res = client.post("/events", json=event.model_dump(mode="json"))
    assert post_res.status_code == 200
    assert post_res.json()["status"] == "processed"

    # Query GET /threats
    response = client.get("/threats", headers=get_auth_headers())
    assert response.status_code == 200
    threats = response.json()
    assert isinstance(threats, list)

    threat = next((t for t in threats if t.get("id") == "pytest-threats-impact-001"), None)
    assert threat is not None, "Persisted threat was not returned by GET /threats"

    # Verify impact assessment exposure
    assert "impact" in threat
    impact = threat["impact"]
    assert impact is not None
    assert impact["impact_identified"] is True
    assert impact["primary_impact"] == "data exposure"
    assert "data exposure" in impact["categories"]
    assert impact["severity"] in ["HIGH", "CRITICAL"]
    assert isinstance(impact["reasons"], list)
    assert len(impact["reasons"]) > 0

    # Verify baseline threat fields are preserved
    assert threat["sourceIp"] == "192.168.1.100"
    assert threat["threatDetected"] is True
    assert threat["action"] in ["BLOCK", "RATE_LIMIT"]
    assert "detectors" in threat


def test_get_threats_endpoint_compromise_impact_assessment(clean_test_events=None):
    """Verify GET /threats exposes endpoint compromise impact for device agent telemetry."""
    if clean_test_events is None or callable(clean_test_events):
        do_cleanup()
    client = TestClient(app)
    laptop_event = ApiSecurityEvent(
        event_id="pytest-threats-endpoint-001",
        timestamp=datetime.now(timezone.utc),
        domain="ENDPOINT",
        network=NetworkInfo(source_ip="192.168.1.150", user_agent="LaptopAgent/1.0"),
        identity=IdentityInfo(user_id="alice", is_authenticated=True),
        request=RequestInfo(method="POST", endpoint="/api/endpoint-telemetry"),
        response=ResponseInfo(status_code=200, latency_ms=12.0),
        resource=ResourceInfo(resource_type="endpoint"),
        endpoint=EndpointInfo(
            event_type="suspicious_process_execution",
            hostname="laptop-alice-x1",
            username="alice",
            process_name="powershell.exe",
            process_id=8192,
            parent_process="cmd.exe",
            executable_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -EncodedCommand SYNTHETIC_DEMO",
            privilege_level="user",
            keyboard_hook=False,
            network_connection=True,
            elevated=False,
        ),
    )

    post_res = client.post("/events", json=laptop_event.model_dump(mode="json"))
    assert post_res.status_code == 200

    response = client.get("/threats", headers=get_auth_headers())
    assert response.status_code == 200
    threats = response.json()

    threat = next((t for t in threats if t.get("id") == "pytest-threats-endpoint-001"), None)
    assert threat is not None

    assert "impact" in threat
    impact = threat["impact"]
    assert impact is not None
    assert impact["impact_identified"] is True
    assert impact["primary_impact"] == "endpoint compromise"
    assert "endpoint compromise" in impact["categories"]
    assert impact["severity"] == "CRITICAL"
    assert threat["action"] == "QUARANTINE"


def test_get_threat_by_id_includes_impact(clean_test_events=None):
    """Verify GET /threats/{event_id} includes impact assessment in the complete threat record."""
    client = TestClient(app)
    event = build_event("pytest-threats-impact-001", "UNION SELECT * FROM users")
    post_res = client.post("/events", json=event.model_dump(mode="json"))
    assert post_res.status_code == 200

    response = client.get("/threats/pytest-threats-impact-001", headers=get_auth_headers())
    assert response.status_code == 200
    data = response.json()

    assert data["event_id"] == "pytest-threats-impact-001"
    assert "processing" in data
    assert "impact" in data["processing"]
    assert data["processing"]["impact"]["impact_identified"] is True
    assert data["processing"]["impact"]["primary_impact"] == "data exposure"
    assert "impact" in data
    assert data["impact"]["primary_impact"] == "data exposure"


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--threats":
        print("Running focused /threats impact exposure tests...")
        test_get_threats_exposes_persisted_impact_assessment()
        print("  test_get_threats_exposes_persisted_impact_assessment PASSED")
        test_get_threats_endpoint_compromise_impact_assessment()
        print("  test_get_threats_endpoint_compromise_impact_assessment PASSED")
        test_get_threat_by_id_includes_impact()
        print("  test_get_threat_by_id_includes_impact PASSED")
        print("\nALL FOCUSED THREATS TESTS PASSED SUCCESSFULLY!")
        sys.exit(0)

    print("Running backend integration, M3-01 telemetry, M3-02 impact, M3-03 resilience, M3-05 ingestion, and M3-05 threats tests...")
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
    test_ml_failure_resilience_in_pipeline()
    print("  test_ml_failure_resilience_in_pipeline PASSED")
    test_recent_events_db_failure_resilience()
    print("  test_recent_events_db_failure_resilience PASSED")
    test_laptop_endpoint_telemetry_pipeline_and_persistence()
    print("  test_laptop_endpoint_telemetry_pipeline_and_persistence PASSED")
    test_mobile_network_telemetry_pipeline_and_persistence()
    print("  test_mobile_network_telemetry_pipeline_and_persistence PASSED")
    test_ml_only_threat_anomaly_impact_classification()
    print("  test_ml_only_threat_anomaly_impact_classification PASSED")
    test_ml_only_benign_produces_no_impact()
    print("  test_ml_only_benign_produces_no_impact PASSED")
    test_post_events_accepts_wrapped_payload()
    print("  test_post_events_accepts_wrapped_payload PASSED")
    test_post_events_accepts_direct_raw_event()
    print("  test_post_events_accepts_direct_raw_event PASSED")
    test_direct_raw_event_triggers_full_processing_pipeline()
    print("  test_direct_raw_event_triggers_full_processing_pipeline PASSED")
    test_direct_invalid_event_returns_422()
    print("  test_direct_invalid_event_returns_422 PASSED")
    test_get_threats_exposes_persisted_impact_assessment()
    print("  test_get_threats_exposes_persisted_impact_assessment PASSED")
    test_get_threats_endpoint_compromise_impact_assessment()
    print("  test_get_threats_endpoint_compromise_impact_assessment PASSED")
    test_get_threat_by_id_includes_impact()
    print("  test_get_threat_by_id_includes_impact PASSED")
    print("\nALL 29 TESTS PASSED SUCCESSFULLY!")
