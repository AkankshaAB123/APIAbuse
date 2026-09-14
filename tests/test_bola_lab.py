from fastapi.testclient import TestClient

from backend.database import events_collection
from backend.lab.bola_lab import vulnerable_resource_request
from backend.main import app


client = TestClient(app)


def test_lab_target_allows_owner_resource_access():
    response = vulnerable_resource_request(
        requester_user_id="user_101",
        requested_resource_id="101",
    )

    assert response["status_code"] == 200
    assert response["unauthorized_access"] is False
    assert response["body"]["owner_id"] == "user_101"


def test_lab_target_observes_bola_condition():
    response = vulnerable_resource_request(
        requester_user_id="user_101",
        requested_resource_id="202",
    )

    assert response["status_code"] == 200
    assert response["unauthorized_access"] is True
    assert response["body"]["owner_id"] == "user_202"


def test_bola_lab_flow_detects_mitigates_and_persists(monkeypatch):
    monkeypatch.setattr(
        "backend.services.event_processor.analyze_threat",
        lambda threat_event: {
            "attack_type": threat_event["attack_type"],
            "risk_score": threat_event["risk_score"],
            "severity": threat_event["severity"],
            "retrieved_documents": [],
            "ai_analysis": {
                "threat_explanation": "BOLA lab test analysis",
                "evidence": "Owner mismatch",
                "risk_assessment": "Critical test risk",
                "recommended_action": "Block request",
            },
        },
    )

    response = client.post("/lab/attacks/bola")

    assert response.status_code == 200

    incident = response.json()
    incident_id = incident["incident_id"]

    try:
        assert incident["classification"] == {
            "level1": "API",
            "level2": "Authorization",
            "level3": "BOLA / IDOR",
        }
        assert incident["attack"]["source_ip"]
        assert incident["attack"]["authentication"] == "Authenticated"
        assert incident["attack"]["target_user"] == "user_202"
        assert incident["attack"]["request"]["query_params"]["requester"] == "user_101"
        assert incident["impact"]["observed"] is True
        assert incident["detection"]["detected"] is True
        assert incident["risk"]["risk_level"] == "CRITICAL"
        assert incident["risk"]["threat_detected"] is True
        assert "BOLA_IDOR" in incident["risk"]["attack_types"]
        assert incident["mitigation"]["action"] == "BLOCK"
        assert incident["mitigation"]["enforced"] is True
        assert incident["mitigation"]["result"] == "REJECTED"
        assert incident["status"] == "MITIGATED"
        assert "MITIGATED" in incident["lifecycle"]["states"]
        assert "REJECTED" in incident["lifecycle"]["states"]
        assert incident["lifecycle"]["timestamps"]["ATTACKING"]

        bola_detector = next(
            detector
            for detector in incident["detection"]["detectors"]
            if detector["detector_id"] == "bola_idor"
        )

        assert bola_detector["detected"] is True
        assert bola_detector["attack_type"] == "BOLA_IDOR"
        assert bola_detector["evidence"][0]["code"] == "RESOURCE_OWNER_MISMATCH"

        stored_event = events_collection.find_one(
            {
                "event_id": incident_id,
            }
        )

        assert stored_event is not None
        assert stored_event["processing"]["mitigation_action"] == "BLOCK"
        assert stored_event["lab_incident"]["status"] == "MITIGATED"
        assert stored_event["lab_incident"]["mitigation"]["result"] == "REJECTED"

    finally:
        events_collection.delete_many(
            {
                "event_id": incident_id,
            }
        )
