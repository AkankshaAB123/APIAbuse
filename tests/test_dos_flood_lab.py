from fastapi.testclient import TestClient

from backend.database import events_collection
from backend.lab.dos_flood_lab import (
    BURST_REQUEST_COUNT,
    LAB_SOURCE,
    POST_MITIGATION_PROBE_COUNT,
    RESOURCE_EXHAUSTION_THRESHOLD,
    flood_target_request,
    reset_flood_lab_state,
)
from backend.main import app


client = TestClient(app)


def test_flood_target_normal_request_succeeds():
    reset_flood_lab_state()

    response = flood_target_request(LAB_SOURCE)

    assert response["status_code"] == 200
    assert response["accepted"] is True


def test_dos_flood_lab_flow_detects_rate_limits_and_persists(monkeypatch):
    reset_flood_lab_state()

    monkeypatch.setattr(
        "backend.lab.dos_flood_lab._send_target_request",
        lambda source: flood_target_request(source),
    )
    monkeypatch.setattr(
        "backend.services.event_processor.analyze_threat",
        lambda threat_event: {
            "attack_type": threat_event["attack_type"],
            "risk_score": threat_event["risk_score"],
            "severity": threat_event["severity"],
            "retrieved_documents": [],
            "ai_analysis": {
                "threat_explanation": "DoS flood lab test analysis",
                "evidence": "High request volume",
                "risk_assessment": "High test risk",
                "recommended_action": "Rate limit source",
            },
        },
    )

    response = client.post("/lab/attacks/dos-flood")

    assert response.status_code == 200

    incident = response.json()
    incident_id = incident["incident_id"]

    try:
        assert incident["classification"] == {
            "level1": "API",
            "level2": "Availability",
            "level3": "DoS / API Flooding / Resource Exhaustion",
        }
        assert incident["attack"]["actual_client_ip"]
        assert incident["attack"]["source_ip"]
        assert incident["attack"]["source_identity_type"]
        assert incident["attack"]["authentication"] == "Unauthenticated / Synthetic traffic generator"
        assert incident["attack"]["target_endpoint"] == "/lab/flood-target"
        assert incident["attack"]["request_count"] == BURST_REQUEST_COUNT
        assert incident["attack"]["request"]["query_params"]["source"] == incident["attack"]["source_ip"]
        assert incident["impact"]["observed"] is True
        assert incident["impact"]["target_response_before_mitigation"][
            "status_code"
        ] == 200
        assert incident["impact"]["target_response_before_mitigation"][
            "accepted_requests"
        ] == BURST_REQUEST_COUNT
        assert incident["impact"]["target_response_before_mitigation"][
            "threshold"
        ] == RESOURCE_EXHAUSTION_THRESHOLD
        assert incident["detection"]["detected"] is True
        assert incident["detection"]["primary_detector"]["detected"] is True
        assert (
            incident["detection"]["primary_detector"]["attack_type"]
            == "RESOURCE_EXHAUSTION"
        )
        assert incident["risk"]["threat_detected"] is True
        assert "RESOURCE_EXHAUSTION" in incident["risk"]["attack_types"]
        assert incident["mitigation"]["action"] == "RATE_LIMIT"
        assert incident["mitigation"]["enforced"] is True
        assert incident["mitigation"]["result"] == "RATE_LIMITED"
        assert (
            incident["mitigation"]["post_mitigation_rejected"]
            == POST_MITIGATION_PROBE_COUNT
        )
        assert incident["status"] == "MITIGATED"
        assert "MITIGATED" in incident["lifecycle"]["states"]
        assert "RATE_LIMITED" in incident["lifecycle"]["states"]
        assert incident["lifecycle"]["timestamps"]["ATTACKING"]

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
        assert (
            stored_event["lab_incident"]["mitigation"]["result"]
            == "RATE_LIMITED"
        )

    finally:
        events_collection.delete_many(
            {
                "event_id": {
                    "$regex": f"^{incident_id}"
                },
            }
        )
        reset_flood_lab_state()
