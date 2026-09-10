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
from backend.services.event_processor import EventProcessor
from backend.services.detection_service import DetectionService
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
    assert data["mitigation_action"] in ["BLOCK", "RATE_LIMIT", "MONITOR"]


if __name__ == "__main__":
    print("Running backend integration and M3-01 telemetry tests...")
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
    print("\nALL 10 TESTS PASSED SUCCESSFULLY!")