from fastapi.testclient import TestClient

from backend.database import events_collection
from backend.lab.phishing_lab import (
    DUMMY_USERNAME,
    PHISHING_PATH,
    build_synthetic_phishing_email_event,
    phishing_page_blocked,
    process_dummy_phishing_submission,
    reset_phishing_lab_state,
)
from backend.main import app
from backend.services.auth_service import create_access_token
from api_detection.backend_adapter import adapt_backend_event
from api_detection.contracts import DetectorDomain
from api_detection.detectors.phishing import detect_phishing


client = TestClient(app)
AUTH_HEADERS = {"Authorization": f"Bearer {create_access_token(data={'sub': 'admin', 'role': 'ADMIN'})}"}


def dynamic_email_payload():
    return {
        "target_enterprise": "ThreatGuard Demo Enterprise",
        "sender": "security-alert@simulated-login.example.test",
        "recipient": "victim_demo@threatguard.example.test",
        "subject": "Account Verification Required",
        "email_body": (
            "Your account requires verification.\n\nPlease verify your account "
            "using the link below."
        ),
        "suspicious_url": "[https://simulated-login.example.test/verify](https://simulated-login.example.test/verify)",
    }


def test_phishing_page_works():
    reset_phishing_lab_state()

    response = client.get(PHISHING_PATH)

    assert response.status_code == 200
    assert "CONTROLLED LOCAL LAB PAGE" in response.text
    assert "victim_demo" in response.text


def test_dummy_submission_observes_impact_without_plaintext_password():
    result = process_dummy_phishing_submission(
        username=DUMMY_USERNAME,
        password="DemoPassword123",
    )

    assert result["status_code"] == 200
    assert result["credential_submission_observed"] is True
    assert result["credential_capture_observed"] is True
    assert result["captured_username"] == DUMMY_USERNAME
    assert result["password_submitted"] is True
    assert result["password_stored_plaintext"] is False
    assert result["body"]["password"] == "REDACTED"
    assert "DemoPassword123" not in str(result)


def test_phishing_lab_flow_detects_blocks_and_persists(monkeypatch):
    reset_phishing_lab_state()

    monkeypatch.setattr(
        "backend.lab.phishing_lab._get_phishing_page",
        lambda: (
            {
                "status_code": 403,
                "body_contains_form": False,
                "latency_ms": 2,
            }
            if phishing_page_blocked()
            else {
                "status_code": 200,
                "body_contains_form": True,
                "latency_ms": 2,
            }
        ),
    )
    monkeypatch.setattr(
        "backend.lab.phishing_lab._submit_dummy_credentials",
        lambda: process_dummy_phishing_submission(
            username=DUMMY_USERNAME,
            password="DemoPassword123",
        ),
    )
    monkeypatch.setattr(
        "backend.services.event_processor.analyze_threat",
        lambda threat_event: {
            "attack_type": threat_event["attack_type"],
            "risk_score": threat_event["risk_score"],
            "severity": threat_event["severity"],
            "retrieved_documents": [],
            "ai_analysis": {
                "threat_explanation": "Phishing lab test analysis",
                "evidence": "Dummy credential submission",
                "risk_assessment": "High test risk",
                "recommended_action": "Block page",
            },
        },
    )

    response = client.post("/lab/attacks/phishing")

    assert response.status_code == 200

    incident = response.json()
    incident_id = incident["incident_id"]

    try:
        assert incident["classification"] == {
            "level1": "ENDPOINT",
            "level2": "Social Engineering / Phishing",
            "level3": "Credential Phishing",
        }
        assert incident["attack"]["source_ip"]
        assert incident["attack"]["authentication"] == "Unauthenticated"
        assert incident["attack"]["target_endpoint"] == PHISHING_PATH
        assert incident["attack"]["payload"]["username"] == DUMMY_USERNAME
        assert incident["attack"]["payload"]["password"] == "REDACTED"
        assert "DemoPassword123" not in str(incident)
        assert incident["impact"]["observed"] is True
        assert incident["impact"]["target_response_before_mitigation"][
            "status_code"
        ] == 200
        assert incident["impact"]["target_response_before_mitigation"][
            "credential_capture_observed"
        ] is True
        assert incident["detection"]["detected"] is True
        assert incident["detection"]["primary_detector"]["detected"] is True
        assert incident["detection"]["primary_detector"]["attack_type"] == "PHISHING"
        assert incident["risk"]["threat_detected"] is True
        assert "PHISHING" in incident["risk"]["attack_types"]
        assert incident["mitigation"]["enforced"] is True
        assert incident["mitigation"]["result"] == "BLOCKED"
        assert (
            incident["mitigation"]["post_mitigation_response"]["status_code"]
            == 403
        )
        assert incident["status"] == "MITIGATED"
        assert "MITIGATED" in incident["lifecycle"]["states"]
        assert "BLOCKED" in incident["lifecycle"]["states"]

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
        assert stored_event["lab_incident"]["mitigation"]["result"] == "BLOCKED"

        threat_response = client.get(
            f"/threats/{incident_id}",
            headers=AUTH_HEADERS,
        )
        assert threat_response.status_code == 200
        assert threat_response.json()["lab_incident"]["attack"][
            "target_endpoint"
        ] == PHISHING_PATH

    finally:
        events_collection.delete_many(
            {
                "event_id": incident_id,
            }
        )
        reset_phishing_lab_state()


def test_dynamic_synthetic_email_uses_existing_detector_result_contract():
    event = build_synthetic_phishing_email_event(
        incident_id="LAB-PHISH-EMAIL-TEST",
        source_ip="127.0.0.1",
        email=dynamic_email_payload(),
    )

    result = detect_phishing(adapt_backend_event(event))

    assert result.event_id == event.event_id
    assert result.detector_id == "phishing"
    assert result.detected is True
    assert result.attack_type.value == "PHISHING"
    assert result.domain == DetectorDomain.ENDPOINT
    assert result.confidence == 0.92
    assert result.severity.value == "HIGH"
    assert {item.code for item in result.evidence} >= {
        "PHISHING_SOCIAL_ENGINEERING_LANGUAGE",
        "PHISHING_SIMULATED_LOGIN_URL",
        "PHISHING_SIMULATED_SENDER_DOMAIN",
        "PHISHING_URL_EMBEDDED_IN_MESSAGE",
    }


def test_dynamic_email_does_not_flag_an_arbitrary_url_without_indicators():
    email = dynamic_email_payload()
    email.update(
        {
            "subject": "Monthly newsletter",
            "email_body": "Read the current lab newsletter at https://portal.example.test/news.",
            "suspicious_url": "https://portal.example.test/news",
        }
    )
    event = build_synthetic_phishing_email_event(
        incident_id="LAB-PHISH-EMAIL-BENIGN",
        source_ip="127.0.0.1",
        email=email,
    )

    result = detect_phishing(adapt_backend_event(event))

    assert result.detected is False
    assert result.attack_type is None
    assert result.domain == DetectorDomain.ENDPOINT


def test_dynamic_synthetic_email_flow_detects_contains_and_persists(monkeypatch):
    monkeypatch.setattr(
        "backend.services.event_processor.analyze_threat",
        lambda threat_event: {
            "attack_type": threat_event["attack_type"],
            "risk_score": threat_event["risk_score"],
            "severity": threat_event["severity"],
            "retrieved_documents": [],
            "ai_analysis": {
                "threat_explanation": "Synthetic phishing email test analysis",
                "evidence": "Reserved login URL and verification language",
                "risk_assessment": "High test risk",
                "recommended_action": "Quarantine synthetic email",
            },
        },
    )

    response = client.post("/lab/attacks/phishing-email", json=dynamic_email_payload())

    assert response.status_code == 200
    incident = response.json()
    incident_id = incident["incident_id"]

    try:
        assert incident["classification"]["level1"] == "ENDPOINT"
        assert incident["attack"]["actual_client_ip"] == "testclient"
        assert incident["attack"]["email"] == {
            "event_type": "synthetic_phishing_email",
            **dynamic_email_payload(),
        }
        assert incident["impact"]["observed"] is True
        before = incident["impact"]["target_response_before_mitigation"]
        assert before["status_code"] == 202
        assert before["external_email_sent"] is False
        assert before["url_contacted"] is False
        assert incident["detection"]["detected"] is True
        assert incident["detection"]["primary_detector"]["attack_type"] == "PHISHING"
        assert incident["risk"]["threat_detected"] is True
        assert incident["mitigation"]["enforced"] is True
        assert incident["mitigation"]["result"] == "CONTAINED"
        assert incident["mitigation"]["post_mitigation_response"]["status_code"] == 403
        assert "QUARANTINE_EMAIL" in incident["mitigation"]["simulated_actions"]
        assert incident["status"] == "MITIGATED"
        assert "CONTAINED" in incident["lifecycle"]["states"]

        stored_event = events_collection.find_one({"event_id": incident_id})
        assert stored_event is not None
        assert stored_event["request"]["body"]["suspicious_url"] == dynamic_email_payload()["suspicious_url"]
        assert stored_event["lab_incident"]["attack"]["email"]["sender"] == dynamic_email_payload()["sender"]

        threat_response = client.get(
            f"/threats/{incident_id}",
            headers=AUTH_HEADERS,
        )
        assert threat_response.status_code == 200
        assert threat_response.json()["lab_incident"]["attack"]["email"]["recipient"] == dynamic_email_payload()["recipient"]
    finally:
        events_collection.delete_many({"event_id": incident_id})
