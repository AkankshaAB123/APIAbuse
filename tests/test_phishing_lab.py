from fastapi.testclient import TestClient

from backend.database import events_collection
from backend.lab.phishing_lab import (
    DUMMY_USERNAME,
    PHISHING_PATH,
    build_phishing_event,
    build_synthetic_phishing_email_event,
    phishing_login_page_html,
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
ADMIN_TOKEN = create_access_token(data={"sub": "admin", "role": "ADMIN"})
AUTH_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


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


def test_victim_browser_get_triggers_pipeline_and_blocks(monkeypatch):
    reset_phishing_lab_state()
    monkeypatch.setattr(
        "backend.services.event_processor.analyze_threat",
        lambda threat_event: {
            "attack_type": threat_event["attack_type"],
            "risk_score": threat_event["risk_score"],
            "severity": threat_event["severity"],
            "retrieved_documents": [],
            "ai_analysis": {
                "threat_explanation": "Victim GET phishing analysis",
                "evidence": "Controlled phishing URL navigation",
                "risk_assessment": "High test risk",
                "recommended_action": "Block page",
            },
        },
    )

    browser_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Host": "10.165.192.186:8000",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    response = client.get(PHISHING_PATH, headers=browser_headers)
    assert response.status_code == 403
    assert "THREATGUARD ACTIVE DEFENSE" in response.text
    assert "Access Blocked (HTTP 403)" in response.text
    assert phishing_page_blocked() is True

    # Confirm the real GET event in MongoDB satisfies all phishing detector contracts
    stored_event = events_collection.find_one(
        {"request.endpoint": PHISHING_PATH, "request.method": "GET"},
        sort=[("timestamp", -1)],
    )
    assert stored_event is not None
    assert stored_event["request"]["method"] == "GET"
    assert stored_event["request"]["body"]["credential_submission_observed"] is True
    assert stored_event["request"]["body"]["credential_capture_observed"] is True
    assert stored_event["request"]["body"]["phishing_url"] == PHISHING_PATH
    assert stored_event["network"]["destination_ip"] == "10.165.192.186"
    assert stored_event["processing"]["risk_assessment"]["threat_detected"] is True
    assert "PHISHING" in stored_event["processing"]["risk_assessment"]["attack_types"]
    assert stored_event["lab_incident"]["status"] == "MITIGATED"

    # Repeated requests remain blocked
    subsequent_response = client.get(PHISHING_PATH, headers=browser_headers)
    assert subsequent_response.status_code == 403


def test_phishing_page_html_served_when_not_detected(monkeypatch):
    reset_phishing_lab_state()
    monkeypatch.setattr(
        "backend.routes.lab.handle_victim_phishing_get",
        lambda **kwargs: (False, phishing_login_page_html(), 200),
    )
    response = client.get(PHISHING_PATH)
    assert response.status_code == 200
    assert "CONTROLLED LOCAL LAB PAGE" in response.text


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

        threat_response = client.get(f"/threats/{incident_id}", headers=AUTH_HEADERS)
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

        threat_response = client.get(f"/threats/{incident_id}", headers=AUTH_HEADERS)
        assert threat_response.status_code == 200
        assert threat_response.json()["lab_incident"]["attack"]["email"]["recipient"] == dynamic_email_payload()["recipient"]
    finally:
        events_collection.delete_many({"event_id": incident_id})


def test_multi_scenario_victim_browser_get_blocks(monkeypatch):
    monkeypatch.setattr(
        "backend.services.event_processor.analyze_threat",
        lambda threat_event: {
            "attack_type": threat_event["attack_type"],
            "risk_score": threat_event["risk_score"],
            "severity": threat_event["severity"],
            "retrieved_documents": [],
            "ai_analysis": {
                "threat_explanation": "Scenario GET phishing analysis",
                "evidence": "Controlled phishing scenario navigation",
                "risk_assessment": "High test risk",
                "recommended_action": "Block scenario page",
            },
        },
    )

    scenarios = ["login", "verify", "reward", "account"]
    for scenario in scenarios:
        reset_phishing_lab_state()
        path = f"/lab/phishing/{scenario}"
        response = client.get(path, headers={"Host": "10.165.192.186:8000"})
        assert response.status_code == 403, f"Scenario {scenario} did not return 403"
        assert "THREATGUARD ACTIVE DEFENSE" in response.text
        assert "Access Blocked (HTTP 403)" in response.text


def test_detector_flags_controlled_scenarios_without_exact_url_hardcoding():
    for endpoint, scenario, lure_type in [
        ("/lab/phishing/verify", "verify", "account_verification"),
        ("/lab/phishing/reward", "reward", "incentive_claim"),
        ("/lab/phishing/account", "account", "security_check"),
    ]:
        body = {
            "scenario": scenario,
            "lure_type": lure_type,
            "has_credential_form": True,
            "social_engineering_terms": ["verify", "urgent", "security alert"],
        }
        event = build_phishing_event(
            incident_id=f"TEST-{scenario}",
            source_ip="127.0.0.1",
            target_response={"status_code": 200, "latency_ms": 1.0, "body": body},
            endpoint=endpoint,
        )
        adapted = adapt_backend_event(event)
        result = detect_phishing(adapted)
        assert result.detected is True
        assert result.attack_type.value == "PHISHING"
        assert any(e.code == "PHISHING_SUSPICIOUS_PATH" for e in result.evidence)
        assert any(e.code == "PHISHING_CREDENTIAL_HARVESTING_FORM" for e in result.evidence)


def test_detector_does_not_flag_benign_endpoints_or_empty_indicators():
    # Path starts with /lab/phishing/ but has no lure marker
    event1 = build_phishing_event(
        incident_id="TEST-BENIGN-1",
        source_ip="127.0.0.1",
        target_response={"status_code": 200, "latency_ms": 1.0, "body": {"info": "Help documentation"}},
        endpoint="/lab/phishing/help",
    )
    result1 = detect_phishing(adapt_backend_event(event1))
    assert result1.detected is False

    # Path has marker but body has no credential form or social engineering
    event2 = build_phishing_event(
        incident_id="TEST-BENIGN-2",
        source_ip="127.0.0.1",
        target_response={"status_code": 200, "latency_ms": 1.0, "body": {"status": "ok"}},
        endpoint="/lab/phishing/account",
    )
    result2 = detect_phishing(adapt_backend_event(event2))
    assert result2.detected is False
