from fastapi.testclient import TestClient

from backend.database import events_collection
from backend.lab.sql_injection_lab import (
    MALICIOUS_SEARCH,
    vulnerable_product_search,
)
from backend.main import app


client = TestClient(app)


def test_lab_target_observes_sql_injection_impact():
    response = vulnerable_product_search(MALICIOUS_SEARCH)

    assert response["status_code"] == 200
    assert response["query_manipulated"] is True
    assert response["safe_parameterized_row_count"] == 0
    assert response["vulnerable_row_count"] > 1


def test_sql_injection_lab_flow_detects_mitigates_and_persists(monkeypatch):
    monkeypatch.setattr(
        "backend.services.event_processor.analyze_threat",
        lambda threat_event: {
            "attack_type": threat_event["attack_type"],
            "risk_score": threat_event["risk_score"],
            "severity": threat_event["severity"],
            "retrieved_documents": [],
            "ai_analysis": {
                "threat_explanation": "SQL injection lab test analysis",
                "evidence": "Injected query parameter",
                "risk_assessment": "High test risk",
                "recommended_action": "Reject request",
            },
        },
    )

    response = client.post("/lab/attacks/sql-injection")

    assert response.status_code == 200

    incident = response.json()
    incident_id = incident["incident_id"]

    try:
        assert incident["classification"] == {
            "level1": "API",
            "level2": "Injection",
            "level3": "SQL Injection",
        }
        assert incident["attack"]["source_ip"]
        assert incident["attack"]["authentication"] == "Authenticated"
        assert incident["attack"]["target_endpoint"] == "/lab/products/search"
        assert incident["attack"]["payload"] == MALICIOUS_SEARCH
        assert incident["attack"]["request"]["query_params"]["query"] == MALICIOUS_SEARCH
        assert incident["impact"]["observed"] is True
        assert (
            incident["impact"]["target_response_before_mitigation"][
                "vulnerable_row_count"
            ]
            > incident["impact"]["target_response_before_mitigation"][
                "safe_parameterized_row_count"
            ]
        )
        assert incident["detection"]["detected"] is True
        assert incident["risk"]["threat_detected"] is True
        assert "SQL_INJECTION" in incident["risk"]["attack_types"]
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

        sql_detector = next(
            detector
            for detector in incident["detection"]["detectors"]
            if detector["detector_id"] == "sql_injection"
        )

        assert sql_detector["detected"] is True
        assert sql_detector["attack_type"] == "SQL_INJECTION"
        assert sql_detector["confidence"] == 0.96

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
