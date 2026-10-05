from fastapi.testclient import TestClient

from backend.database import events_collection
from backend.lab.ssrf_lab import (
    INTERNAL_RESTRICTED_URL,
    vulnerable_ssrf_fetch,
)
from backend.main import app


client = TestClient(app)


def test_restricted_internal_resource_endpoint_returns_synthetic_data():
    response = client.get("/lab/internal/restricted")

    assert response.status_code == 200
    assert response.json()["resource"] == "restricted-internal-lab-service"


def test_lab_target_observes_ssrf_impact(monkeypatch):
    monkeypatch.setattr(
        "backend.lab.ssrf_lab._perform_server_side_request",
        lambda target_url: {
            "status_code": 200,
            "body": '{"resource":"restricted-internal-lab-service"}',
            "headers": {},
        },
    )

    response = vulnerable_ssrf_fetch(INTERNAL_RESTRICTED_URL)

    assert response["status_code"] == 200
    assert response["restricted_resource_reached"] is True
    assert response["target_url"] == INTERNAL_RESTRICTED_URL


def test_ssrf_lab_flow_detects_mitigates_and_persists(monkeypatch):
    monkeypatch.setattr(
        "backend.lab.ssrf_lab._perform_server_side_request",
        lambda target_url: {
            "status_code": 200,
            "body": '{"resource":"restricted-internal-lab-service"}',
            "headers": {},
        },
    )
    monkeypatch.setattr(
        "backend.services.event_processor.analyze_threat",
        lambda threat_event: {
            "attack_type": threat_event["attack_type"],
            "risk_score": threat_event["risk_score"],
            "severity": threat_event["severity"],
            "retrieved_documents": [],
            "ai_analysis": {
                "threat_explanation": "SSRF lab test analysis",
                "evidence": "Restricted localhost URL",
                "risk_assessment": "High test risk",
                "recommended_action": "Reject request",
            },
        },
    )

    response = client.post("/lab/attacks/ssrf")

    assert response.status_code == 200

    incident = response.json()
    incident_id = incident["incident_id"]

    try:
        assert incident["classification"] == {
            "level1": "API",
            "level2": "Server-Side Request",
            "level3": "SSRF",
        }
        assert incident["attack"]["source_ip"]
        assert incident["attack"]["authentication"] == "Authenticated"
        assert incident["attack"]["target_endpoint"] == "/lab/fetch"
        assert incident["attack"]["payload"]["url"] == INTERNAL_RESTRICTED_URL
        assert incident["attack"]["request"]["body"]["url"] == INTERNAL_RESTRICTED_URL
        assert incident["impact"]["observed"] is True
        assert incident["detection"]["detected"] is True
        assert incident["risk"]["threat_detected"] is True
        assert "SSRF" in incident["risk"]["attack_types"]
        assert incident["mitigation"]["enforced"] is True
        assert incident["mitigation"]["result"] == "REJECTED"
        assert (
            incident["mitigation"]["post_mitigation_response"]["status_code"]
            == 403
        )
        assert incident["status"] == "MITIGATED"
        assert "MITIGATED" in incident["lifecycle"]["states"]
        assert "REJECTED" in incident["lifecycle"]["states"]
        assert incident["lifecycle"]["timestamps"]["ATTACKING"]

        ssrf_detector = next(
            detector
            for detector in incident["detection"]["detectors"]
            if detector["detector_id"] == "ssrf"
        )

        assert ssrf_detector["detected"] is True
        assert ssrf_detector["attack_type"] == "SSRF"
        assert ssrf_detector["confidence"] == 0.95

        stored_event = events_collection.find_one(
            {
                "event_id": incident_id,
            }
        )

        assert stored_event is not None
        assert stored_event["processing"]["risk_assessment"][
            "threat_detected"
        ] is True
        assert stored_event["lab_incident"]["status"] == "MITIGATED"
        assert stored_event["lab_incident"]["mitigation"]["result"] == "REJECTED"

    finally:
        events_collection.delete_many(
            {
                "event_id": incident_id,
            }
        )
