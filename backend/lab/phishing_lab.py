import json
from datetime import datetime, timezone
from time import perf_counter
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from backend.database import events_collection
from backend.schemas.api_security_event import (
    ApiSecurityEvent,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResourceInfo,
    ResponseInfo,
)
from backend.services.event_processor import EventProcessor


CLASSIFICATION = {
    "level1": "ENDPOINT",
    "level2": "Social Engineering / Phishing",
    "level3": "Credential Phishing",
}

PHISHING_PATH = "/lab/phishing/login"
PHISHING_URL = "http://127.0.0.1:8000/lab/phishing/login"
PHISHING_EMAIL_PATH = "/lab/phishing/email"
DUMMY_USERNAME = "victim_demo"
DUMMY_PASSWORD = "DemoPassword123"

SCENARIO_CONFIGS = {
    "login": {
        "title": "Account Login",
        "badge": "CONTROLLED LOCAL LAB PAGE",
        "description": "This intentionally fake login page is used only with dummy lab credentials.",
        "lure_type": "credential_harvesting",
        "fields": ["username", "password"],
        "terms": ["login", "sign in", "credential", "password"],
    },
    "verify": {
        "title": "Account Verification Required",
        "badge": "CONTROLLED LOCAL VERIFICATION PAGE",
        "description": "Urgent security alert: please verify your account immediately to avoid suspension.",
        "lure_type": "account_verification",
        "fields": ["username", "verification_code"],
        "terms": ["verify", "verification", "urgent", "immediately", "security alert", "suspended"],
    },
    "reward": {
        "title": "Claim Exclusive Reward",
        "badge": "CONTROLLED LOCAL REWARD PAGE",
        "description": "Claim your security promotion bonus voucher immediately by confirming your user identity.",
        "lure_type": "incentive_claim",
        "fields": ["username", "claim_code"],
        "terms": ["reward", "claim", "bonus", "voucher", "promotion", "gift"],
    },
    "account": {
        "title": "Account Security Update",
        "badge": "CONTROLLED LOCAL ACCOUNT PORTAL",
        "description": "Review and update your enterprise account profile and credentials immediately.",
        "lure_type": "security_check",
        "fields": ["username", "account_pin"],
        "terms": ["account", "security alert", "password", "credential", "immediately"],
    },
}

_PHISHING_BLOCKED = False
_BLOCKED_PHISHING_SCENARIOS: set[str] = set()


def reset_phishing_lab_state() -> None:
    global _PHISHING_BLOCKED, _BLOCKED_PHISHING_SCENARIOS
    _PHISHING_BLOCKED = False
    _BLOCKED_PHISHING_SCENARIOS = set()


def block_phishing_page(scenario: str | None = None) -> None:
    global _PHISHING_BLOCKED, _BLOCKED_PHISHING_SCENARIOS
    _PHISHING_BLOCKED = True
    if scenario:
        _BLOCKED_PHISHING_SCENARIOS.add(scenario)


def phishing_page_blocked(scenario: str | None = None) -> bool:
    if scenario and scenario in _BLOCKED_PHISHING_SCENARIOS:
        return True
    return _PHISHING_BLOCKED


def phishing_login_page_html(scenario: str = "login") -> str:
    cfg = SCENARIO_CONFIGS.get(scenario, SCENARIO_CONFIGS["login"])
    badge = cfg["badge"]
    title = cfg["title"]
    desc = cfg["description"]
    action_endpoint = f"/lab/phishing/{scenario}"

    return f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <title>ThreatGuard Controlled Phishing Lab - {title}</title>
        <style>
          body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
            font-family: Arial, sans-serif; background: #060914; color: #e7eaf6; }}
          main {{ width: min(420px, 92vw); padding: 28px; border: 1px solid #253255;
            border-radius: 10px; background: #10162a; box-shadow: 0 24px 80px #0008; }}
          .lab {{ color: #fbbf24; font-size: 12px; font-weight: 700; letter-spacing: .08em; }}
          h1 {{ margin: 10px 0 4px; font-size: 28px; }}
          p {{ color: #93a4c7; line-height: 1.5; }}
          label {{ display: block; margin-top: 16px; color: #b8c3df; font-size: 13px; }}
          input {{ width: 100%; box-sizing: border-box; margin-top: 8px; padding: 12px;
            border-radius: 8px; border: 1px solid #33415f; background: #070b18; color: #fff; }}
          button {{ margin-top: 20px; width: 100%; padding: 12px; border: 0;
            border-radius: 8px; background: #2563eb; color: white; font-weight: 700; }}
        </style>
      </head>
      <body>
        <main>
          <div class="lab">{badge}</div>
          <h1>{title}</h1>
          <p>{desc}</p>
          <form id="login-form">
            <label>Username / Account ID
              <input name="username" value="victim_demo" autocomplete="off" />
            </label>
            <label>Credential / Security PIN
              <input name="password" value="DemoPassword123" type="password" autocomplete="off" />
            </label>
            <button type="submit">Continue</button>
          </form>
          <script>
            document.getElementById("login-form").addEventListener("submit", async (event) => {{
              event.preventDefault();
              const form = new FormData(event.currentTarget);
              await fetch("{action_endpoint}", {{
                method: "POST",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify({{
                  username: form.get("username"),
                  password: form.get("password")
                }})
              }});
            }});
          </script>
        </main>
      </body>
    </html>
    """


def phishing_blocked_page_html(
    incident_id: str | None = None,
    risk_score: float | None = None,
    action: str = "BLOCKED",
) -> str:
    incident_label = f"Incident ID: {incident_id}" if incident_id else "Real-time Interception"
    risk_label = f"Risk Score: {risk_score:.1f} (HIGH)" if risk_score is not None else "High Risk Phishing Target"
    return f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <title>ThreatGuard Active Defense - Phishing Site Blocked</title>
        <style>
          body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
            font-family: Arial, sans-serif; background: #060914; color: #e7eaf6; }}
          main {{ width: min(480px, 92vw); padding: 32px; border: 1px solid #ef4444;
            border-radius: 12px; background: #10162a; box-shadow: 0 24px 80px rgba(239, 68, 68, 0.25); text-align: center; }}
          .badge {{ display: inline-block; padding: 4px 14px; border-radius: 20px;
            background: rgba(239, 68, 68, 0.15); color: #ef4444; font-size: 11px; font-weight: 700; letter-spacing: .08em; border: 1px solid #ef4444; }}
          h1 {{ margin: 16px 0 8px; font-size: 26px; color: #f87171; }}
          p {{ color: #93a4c7; line-height: 1.6; font-size: 14px; margin: 8px 0; }}
          .details {{ margin-top: 20px; padding: 16px; border-radius: 8px; background: #070b18; border: 1px solid #253255; text-align: left; }}
          .details div {{ margin-bottom: 8px; font-size: 13px; color: #b8c3df; }}
          .details div:last-child {{ margin-bottom: 0; }}
          .details strong {{ color: #e7eaf6; }}
          .footer {{ margin-top: 24px; font-size: 12px; color: #64748b; }}
        </style>
      </head>
      <body>
        <main>
          <div class="badge">THREATGUARD ACTIVE DEFENSE</div>
          <h1>Access Blocked (HTTP 403)</h1>
          <p>This destination was identified as a <strong>controlled credential phishing site</strong> and blocked by ThreatGuard in real time.</p>
          <div class="details">
            <div><strong>Detection:</strong> Phishing Credential Interception</div>
            <div><strong>Threat:</strong> Social Engineering / Credential Harvesting</div>
            <div><strong>Assessment:</strong> {risk_label}</div>
            <div><strong>Enforcement:</strong> {action} Enforced</div>
            <div><strong>Tracking:</strong> {incident_label}</div>
          </div>
          <div class="footer">ThreatGuard Autonomous Security Gateway &copy; 2026</div>
        </main>
      </body>
    </html>
    """


def handle_victim_phishing_get(
    scenario: str = "login",
    source_ip: str = "127.0.0.1",
    destination_ip: str = "10.165.192.186",
    user_agent: str = "Victim-Browser",
) -> tuple[bool, str, int]:
    """Process a real victim browser GET request to the controlled phishing URL.

    Executes the existing detection -> RAG/LLM -> risk -> mitigation pipeline.
    Returns (is_blocked, html_content, status_code).
    """
    if phishing_page_blocked(scenario):
        return True, phishing_blocked_page_html(), 403

    cfg = SCENARIO_CONFIGS.get(scenario, SCENARIO_CONFIGS["login"])
    scenario_path = f"/lab/phishing/{scenario}"
    incident_id = f"LAB-PHISH-GET-{uuid4().hex[:10]}"
    target_response = {
        "status_code": 200,
        "latency_ms": 1.0,
        "body": {
            "scenario": scenario,
            "lure_type": cfg["lure_type"],
            "has_credential_form": True,
            "page_contains_login_form": True,
            "social_engineering_terms": cfg["terms"],
            "credential_submission_observed": True,
            "credential_capture_observed": True,
            "phishing_url": scenario_path,
            "captured_username": DUMMY_USERNAME,
            "password_submitted": False,
            "message": f"Victim browser navigated to controlled phishing {scenario} URL.",
        },
    }

    event = build_phishing_event(
        incident_id=incident_id,
        source_ip=source_ip,
        target_response=target_response,
        endpoint=scenario_path,
    )
    event.request.method = "GET"
    event.network.user_agent = user_agent
    event.network.destination_ip = destination_ip

    processor = EventProcessor()
    processing_result = processor.process(event)

    detector = _phishing_detector(processing_result)
    detected = bool(
        (detector and detector.get("detected"))
        or (processing_result.risk_assessment and processing_result.risk_assessment.threat_detected)
    )

    if detected:
        block_phishing_page(scenario)

        incident_doc = {
            "incident_id": incident_id,
            "classification": CLASSIFICATION,
            "attack": {
                "name": "Credential Phishing",
                "attacker": "victim-browser-click",
                "actual_client_ip": source_ip,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "authentication": "Unauthenticated",
                "target_endpoint": scenario_path,
                "method": "GET",
                "payload": {
                    "username": DUMMY_USERNAME,
                    "password_submitted": False,
                },
                "attacker_request": f"GET {scenario_path}",
                "request": {
                    "method": "GET",
                    "endpoint": scenario_path,
                    "body": event.request.body,
                },
            },
            "impact": {
                "observed": True,
                "description": f"Victim browser opened controlled phishing {scenario} URL; active defense intercepted the request.",
                "target_response_before_mitigation": {
                    "status_code": 200,
                    "page_contains_login_form": True,
                    "credential_submission_observed": True,
                    "credential_capture_observed": True,
                },
            },
            "detection": {
                "method": "existing_detector_pipeline_phishing_detector",
                "detected": True,
                "primary_detector": detector,
                "detectors": [
                    result.model_dump()
                    for result in processing_result.detector_results
                ],
            },
            "risk": (
                processing_result.risk_assessment.model_dump()
                if processing_result.risk_assessment
                else None
            ),
            "mitigation": {
                "action": processing_result.mitigation_action or "URL_BLOCK",
                "enforced": True,
                "result": "BLOCKED",
                "description": "ThreatGuard Active Defense blocked the controlled phishing site in real-time.",
                "post_mitigation_response": {
                    "status_code": 403,
                    "body": {
                        "error": "page_blocked",
                        "reason": f"Controlled phishing navigation detected on {scenario_path}",
                    },
                },
            },
            "lifecycle": {
                "states": [
                    "ATTACKING",
                    "IMPACT_OBSERVED",
                    "DETECTED",
                    "MITIGATING",
                    "MITIGATED",
                    "BLOCKED",
                ],
                "timestamps": {
                    "ATTACKING": datetime.now(timezone.utc).isoformat(),
                    "DETECTED": datetime.now(timezone.utc).isoformat(),
                    "MITIGATED": datetime.now(timezone.utc).isoformat(),
                    "BLOCKED": datetime.now(timezone.utc).isoformat(),
                },
            },
            "status": "MITIGATED",
            "processing_result": processing_result.model_dump(),
        }
        events_collection.update_one(
            {"event_id": incident_id},
            {"$set": {"lab_incident": incident_doc, "network.destination_ip": destination_ip}},
        )

        risk_score = (
            processing_result.risk_assessment.risk_score
            if processing_result.risk_assessment
            else None
        )
        action = processing_result.mitigation_action or "URL_BLOCK"
        return True, phishing_blocked_page_html(
            incident_id=incident_id,
            risk_score=risk_score,
            action=action,
        ), 403

    return False, phishing_login_page_html(scenario=scenario), 200


def process_dummy_phishing_submission(username: str, password: str) -> dict:
    password_submitted = bool(password)

    return {
        "status_code": 200,
        "body": {
            "credential_submission_observed": True,
            "credential_capture_observed": bool(username and password_submitted),
            "captured_username": username,
            "password_submitted": password_submitted,
            "password": "REDACTED" if password_submitted else None,
            "phishing_url": PHISHING_PATH,
            "message": "Dummy credential interaction captured by controlled phishing lab.",
        },
        "latency_ms": 12,
        "credential_submission_observed": True,
        "credential_capture_observed": bool(username and password_submitted),
        "captured_username": username,
        "password_submitted": password_submitted,
        "password_stored_plaintext": False,
        "description": (
            "A synthetic victim submitted dummy credentials to the controlled "
            "local phishing page."
        ),
    }


def _get_phishing_page() -> dict:
    started = perf_counter()

    try:
        with urlopen(PHISHING_URL, timeout=5) as response:
            body = response.read().decode("utf-8", errors="replace")
            return {
                "status_code": response.status,
                "body_contains_form": "<form" in body,
                "latency_ms": round((perf_counter() - started) * 1000, 2),
            }
    except HTTPError as exc:
        exc.read()
        return {
            "status_code": exc.code,
            "body_contains_form": False,
            "latency_ms": round((perf_counter() - started) * 1000, 2),
        }


def _submit_dummy_credentials() -> dict:
    started = perf_counter()
    payload = json.dumps(
        {
            "username": DUMMY_USERNAME,
            "password": DUMMY_PASSWORD,
        }
    ).encode("utf-8")
    request = Request(
        PHISHING_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ThreatGuard-Phishing-Lab-Victim",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=5) as response:
            body = json.loads(response.read().decode("utf-8"))
            body["latency_ms"] = round((perf_counter() - started) * 1000, 2)
            return body
    except URLError as exc:
        return {
            "status_code": 0,
            "body": {
                "error": "dummy_submission_failed",
                "message": str(exc),
            },
            "latency_ms": round((perf_counter() - started) * 1000, 2),
            "credential_capture_observed": False,
        }


def build_phishing_event(
    incident_id: str,
    source_ip: str,
    target_response: dict,
    endpoint: str = PHISHING_PATH,
) -> ApiSecurityEvent:
    body = target_response["body"]

    request_body = {
        "username": body.get("captured_username"),
        "password_submitted": body.get("password_submitted"),
        "credential_submission_observed": body.get(
            "credential_submission_observed"
        ),
        "credential_capture_observed": body.get(
            "credential_capture_observed"
        ),
        "phishing_url": body.get("phishing_url", endpoint),
    }
    if "has_credential_form" in body:
        request_body["has_credential_form"] = body["has_credential_form"]
    if "page_contains_login_form" in body:
        request_body["page_contains_login_form"] = body["page_contains_login_form"]
    if "social_engineering_terms" in body:
        request_body["social_engineering_terms"] = body["social_engineering_terms"]
    if "lure_type" in body:
        request_body["lure_type"] = body["lure_type"]
    if "scenario" in body:
        request_body["scenario"] = body["scenario"]

    return ApiSecurityEvent(
        event_id=incident_id,
        timestamp=datetime.now(timezone.utc),
        network=NetworkInfo(
            source_ip=source_ip,
            user_agent="ThreatGuard-Phishing-Lab",
        ),
        identity=IdentityInfo(
            user_id=body.get("captured_username"),
            session_id="lab-session-phishing",
            roles=[],
            is_authenticated=False,
        ),
        request=RequestInfo(
            method="POST",
            endpoint=endpoint,
            query_params={},
            headers={
                "X-ThreatGuard-Lab": "PHISHING",
            },
            body=request_body,
        ),
        response=ResponseInfo(
            status_code=target_response["status_code"],
            latency_ms=target_response["latency_ms"],
        ),
        resource=ResourceInfo(
            resource_type="phishing_page",
            resource_id=endpoint,
            owner_id="threatguard-lab",
            is_sensitive=True,
        ),
    )


def build_synthetic_phishing_email_event(
    incident_id: str,
    source_ip: str,
    email: dict,
) -> ApiSecurityEvent:
    """Represent a local synthetic email using the existing request body contract."""
    return ApiSecurityEvent(
        event_id=incident_id,
        timestamp=datetime.now(timezone.utc),
        network=NetworkInfo(
            source_ip=source_ip,
            user_agent="ThreatGuard-Synthetic-Phishing-Email",
        ),
        identity=IdentityInfo(
            user_id=None,
            session_id=f"lab-email-{incident_id}",
            roles=[],
            is_authenticated=False,
        ),
        request=RequestInfo(
            method="POST",
            endpoint=PHISHING_EMAIL_PATH,
            headers={"X-ThreatGuard-Lab": "SYNTHETIC_PHISHING_EMAIL"},
            body={
                "event_type": "synthetic_phishing_email",
                "target_enterprise": email["target_enterprise"],
                "sender": email["sender"],
                "recipient": email["recipient"],
                "subject": email["subject"],
                "email_body": email["email_body"],
                "suspicious_url": email["suspicious_url"],
            },
        ),
        response=ResponseInfo(status_code=202, latency_ms=1.0),
        resource=ResourceInfo(
            resource_type="synthetic_enterprise_email",
            resource_id=email["recipient"],
            owner_id=email["target_enterprise"],
            is_sensitive=True,
        ),
    )


def _phishing_detector(processing_result) -> dict | None:
    for result in processing_result.detector_results:
        if result.detector_id == "phishing":
            return result.model_dump()
    return None


def enforce_lab_mitigation(processing_result) -> dict:
    recommended_action = processing_result.mitigation_action
    detector = _phishing_detector(processing_result)
    enforced = bool(detector and detector["detected"])

    if enforced:
        block_phishing_page()

    probe = _get_phishing_page()

    return {
        "action": recommended_action,
        "enforced": enforced,
        "result": "BLOCKED" if enforced else "ALLOWED",
        "description": (
            "ThreatGuard lab enforcement blocked the local phishing page."
            if enforced
            else "ThreatGuard lab enforcement allowed the local phishing page."
        ),
        "post_mitigation_response": {
            "status_code": probe["status_code"],
            "body": (
                {
                    "error": "page_blocked",
                    "reason": "Controlled phishing credential capture detected",
                }
                if enforced
                else {
                    "status": "allowed",
                }
            ),
        },
    }


def run_phishing_attack_lab(source_ip: str = "127.0.0.1") -> dict:
    reset_phishing_lab_state()

    incident_id = f"LAB-PHISH-{uuid4().hex[:10]}"
    timestamps = {
        "ATTACKING": datetime.now(timezone.utc).isoformat(),
    }

    page_response = _get_phishing_page()
    submission_response = _submit_dummy_credentials()
    timestamps["IMPACT_OBSERVED"] = datetime.now(timezone.utc).isoformat()

    event = build_phishing_event(
        incident_id=incident_id,
        source_ip=source_ip,
        target_response=submission_response,
    )

    processor = EventProcessor()
    processing_result = processor.process(event)

    timestamps["DETECTED"] = datetime.now(timezone.utc).isoformat()
    timestamps["MITIGATING"] = datetime.now(timezone.utc).isoformat()

    mitigation = enforce_lab_mitigation(processing_result)

    timestamps["MITIGATED"] = datetime.now(timezone.utc).isoformat()
    timestamps[mitigation["result"]] = timestamps["MITIGATED"]

    detector = _phishing_detector(processing_result)
    impact_observed = (
        page_response["status_code"] == 200
        and page_response["body_contains_form"]
        and submission_response.get("credential_capture_observed") is True
    )

    incident = {
        "incident_id": incident_id,
        "classification": CLASSIFICATION,
        "attack": {
            "name": "Credential Phishing",
            "attacker": "local-phishing-lab",
            "source_ip": source_ip,
            "authentication": "Unauthenticated",
            "target_endpoint": PHISHING_PATH,
            "method": "POST",
            "payload": {
                "username": DUMMY_USERNAME,
                "password_submitted": True,
                "password": "REDACTED",
            },
            "attacker_request": f"GET {PHISHING_PATH} -> POST {PHISHING_PATH}",
            "request": {
                "method": "POST",
                "endpoint": PHISHING_PATH,
                "body": event.request.body,
            },
        },
        "impact": {
            "observed": impact_observed,
            "description": submission_response["description"],
            "target_response_before_mitigation": {
                "status_code": submission_response["status_code"],
                "page_status_code": page_response["status_code"],
                "page_contains_login_form": page_response["body_contains_form"],
                "credential_submission_observed": submission_response[
                    "credential_submission_observed"
                ],
                "credential_capture_observed": submission_response[
                    "credential_capture_observed"
                ],
                "captured_username": submission_response["captured_username"],
                "password_submitted": submission_response["password_submitted"],
                "password": "REDACTED",
                "password_stored_plaintext": False,
            },
        },
        "detection": {
            "method": "existing_detector_pipeline_phishing_detector",
            "detected": processing_result.risk_assessment.threat_detected,
            "primary_detector": detector,
            "detectors": [
                result.model_dump()
                for result in processing_result.detector_results
            ],
        },
        "risk": (
            processing_result.risk_assessment.model_dump()
            if processing_result.risk_assessment is not None
            else None
        ),
        "mitigation": mitigation,
        "lifecycle": {
            "states": [
                "ATTACKING",
                "IMPACT_OBSERVED",
                "DETECTED",
                "MITIGATING",
                "MITIGATED",
                mitigation["result"],
            ],
            "timestamps": timestamps,
        },
        "status": "MITIGATED" if mitigation["enforced"] else "OBSERVED",
        "processing_result": processing_result.model_dump(),
    }

    events_collection.update_one(
        {
            "event_id": incident_id,
        },
        {
            "$set": {
                "lab_incident": incident,
            }
        },
    )

    return incident


def run_synthetic_phishing_email_lab(email: dict, source_ip: str) -> dict:
    """Process a user-authored synthetic email without sending it externally."""
    incident_id = f"LAB-PHISH-EMAIL-{uuid4().hex[:10]}"
    timestamps = {"ATTACKING": datetime.now(timezone.utc).isoformat()}
    arrival_timestamp = datetime.now(timezone.utc).isoformat()
    event = build_synthetic_phishing_email_event(incident_id, source_ip, email)

    # The only delivery here is storage in this controlled lab event. No SMTP,
    # URL request, or external interaction is performed.
    impact = {
        "observed": True,
        "description": "Synthetic email arrived in the controlled enterprise inbox for IDS analysis.",
        "potential_consequences": [
            "Simulated credential compromise risk",
            "Possible simulated account takeover",
            "Possible simulated unauthorized access",
            "Possible simulated data exposure",
        ],
        "target_response_before_mitigation": {
            "status_code": 202,
            "delivery": "SYNTHETIC_EMAIL_ARRIVED",
            "arrival_timestamp": arrival_timestamp,
            "external_email_sent": False,
            "url_contacted": False,
        },
    }
    timestamps["IMPACT_OBSERVED"] = datetime.now(timezone.utc).isoformat()

    processing_result = EventProcessor().process(event)
    detector = _phishing_detector(processing_result)
    detected = bool(detector and detector["detected"])
    timestamps["DETECTED"] = datetime.now(timezone.utc).isoformat()
    timestamps["MITIGATING"] = datetime.now(timezone.utc).isoformat()

    mitigation = {
        "action": processing_result.mitigation_action,
        "enforced": detected,
        "result": "CONTAINED" if detected else "DELIVERED",
        "simulated_actions": (
            [
                "QUARANTINE_EMAIL",
                "BLOCK_URL",
                "FLAG_SENDER",
                "PREVENT_SIMULATED_LINK_INTERACTION",
            ]
            if detected
            else []
        ),
        "description": (
            "ThreatGuard quarantined the synthetic email and prevented simulated "
            "link interaction. No external email or URL was contacted."
            if detected
            else "Synthetic email remained available because no phishing rule matched."
        ),
        "post_mitigation_response": {
            "status_code": 403 if detected else 202,
            "delivery": "QUARANTINED" if detected else "DELIVERED",
            "simulated_link_interaction": "PREVENTED" if detected else "NOT_BLOCKED",
        },
    }
    timestamps["MITIGATED"] = datetime.now(timezone.utc).isoformat()
    timestamps[mitigation["result"]] = timestamps["MITIGATED"]

    incident = {
        "incident_id": incident_id,
        "classification": CLASSIFICATION,
        "attack": {
            "name": "Credential Phishing",
            "attacker": "synthetic-email-lab",
            "actual_client_ip": source_ip,
            "source_ip": source_ip,
            "authentication": "Unauthenticated",
            "target_endpoint": PHISHING_EMAIL_PATH,
            "method": "POST",
            "email": event.request.body,
            "request": {"method": "POST", "endpoint": PHISHING_EMAIL_PATH, "body": event.request.body},
        },
        "impact": impact,
        "detection": {
            "method": "existing_detector_pipeline_phishing_detector",
            "detected": detected,
            "primary_detector": detector,
            "detectors": [result.model_dump() for result in processing_result.detector_results],
        },
        "risk": processing_result.risk_assessment.model_dump(),
        "mitigation": mitigation,
        "lifecycle": {
            "states": ["ATTACKING", "IMPACT_OBSERVED", "DETECTED", "MITIGATING", "MITIGATED", mitigation["result"]],
            "timestamps": timestamps,
        },
        "status": "MITIGATED" if detected else "OBSERVED",
        "processing_result": processing_result.model_dump(),
    }
    events_collection.update_one({"event_id": incident_id}, {"$set": {"lab_incident": incident}})
    return incident
