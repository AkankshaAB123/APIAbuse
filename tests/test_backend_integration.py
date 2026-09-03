import pytest
from backend.database import events_collection

from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.main import app
from backend.schemas.api_security_event import (
    ApiSecurityEvent,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResourceInfo,
    ResponseInfo,
)
from backend.services.event_processor import EventProcessor


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


@pytest.fixture
def clean_test_events():
    yield
    for event_id in [
        "pytest-sqli-001",
        "pytest-benign-001",
        "pytest-persistence-001",
    ]:
        events_collection.delete_many({"event_id": event_id})



def test_sql_injection_triggers_block(clean_test_events):
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
    assert result.risk_assessment.risk_score == 96.0
    assert result.risk_assessment.risk_level == "CRITICAL"
    assert result.risk_assessment.threat_detected is True

    assert result.mitigation_action == "BLOCK"


def test_benign_event_allows_request(clean_test_events):
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



def test_processing_result_is_persisted(clean_test_events):
    processor = EventProcessor()
    event = build_event("pytest-persistence-001", "UNION SELECT")

    result = processor.process(event)

    stored_event = events_collection.find_one(
        {"event_id": event.event_id}
    )

    assert stored_event is not None
    assert "processing" in stored_event
    assert len(stored_event["processing"]["detector_results"]) == 10
    assert stored_event["processing"]["risk_assessment"]["risk_level"] == "CRITICAL"
    assert stored_event["processing"]["mitigation_action"] == "BLOCK"


def test_event_processing_failure_returns_500(monkeypatch):
    client = TestClient(app)

    def failing_process(*args, **kwargs):
        raise RuntimeError("Simulated processing failure")

    monkeypatch.setattr(
        "backend.routes.events.processor.process",
        failing_process,
    )

    event = build_event("pytest-error-001", "laptop")

    response = client.post(
        "/events",
        json={"event": event.model_dump(mode="json")},
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "Event processing failed"}