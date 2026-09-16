from datetime import datetime, timezone
from time import perf_counter
from urllib.error import URLError
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
    "level1": "API",
    "level2": "Server-Side Request",
    "level3": "SSRF",
}

INTERNAL_RESTRICTED_PATH = "/lab/internal/restricted"
INTERNAL_RESTRICTED_URL = "http://127.0.0.1:8000/lab/internal/restricted"


def restricted_internal_resource() -> dict:
    return {
        "resource": "restricted-internal-lab-service",
        "classification": "internal-only",
        "synthetic_secret": "demo-internal-token",
        "message": "Restricted lab resource reached by server-side request.",
    }


def _perform_server_side_request(target_url: str) -> dict:
    request = Request(
        target_url,
        headers={
            "User-Agent": "ThreatGuard-SSRF-Lab-Target",
        },
    )

    with urlopen(request, timeout=5) as response:
        body = response.read().decode("utf-8", errors="replace")
        return {
            "status_code": response.status,
            "body": body,
            "headers": dict(response.headers),
        }


def vulnerable_ssrf_fetch(target_url: str) -> dict:
    """
    Deliberately vulnerable SSRF lab target.

    It accepts a user-supplied URL and performs a server-side HTTP request.
    The safety guard only permits this intentionally restricted localhost
    lab endpoint, never external infrastructure or real internal networks.
    """

    if target_url != INTERNAL_RESTRICTED_URL:
        return {
            "status_code": 400,
            "body": {
                "error": "unsafe_lab_url",
                "message": "Only the controlled local restricted endpoint is allowed.",
            },
            "latency_ms": 0,
            "target_url": target_url,
            "restricted_resource_reached": False,
            "description": "The lab refused a URL outside the controlled SSRF target.",
        }

    started = perf_counter()

    try:
        response = _perform_server_side_request(target_url)
        latency_ms = round((perf_counter() - started) * 1000, 2)
        restricted_reached = (
            response["status_code"] == 200
            and "restricted-internal-lab-service" in response["body"]
        )

        return {
            "status_code": 200,
            "body": {
                "requested_url": target_url,
                "server_side_response": response,
            },
            "latency_ms": latency_ms,
            "target_url": target_url,
            "restricted_resource_reached": restricted_reached,
            "description": (
                "The vulnerable lab target reached a restricted internal "
                "localhost resource through a server-side request."
                if restricted_reached
                else "The server-side request completed without reaching the restricted resource."
            ),
        }
    except URLError as exc:
        latency_ms = round((perf_counter() - started) * 1000, 2)
        return {
            "status_code": 502,
            "body": {
                "error": "server_side_request_failed",
                "message": str(exc),
            },
            "latency_ms": latency_ms,
            "target_url": target_url,
            "restricted_resource_reached": False,
            "description": "The vulnerable lab target could not complete the server-side request.",
        }


def build_ssrf_event(
    incident_id: str,
    attacker_user_id: str,
    target_url: str,
    target_response: dict,
    source_ip: str = "127.0.0.1",
) -> ApiSecurityEvent:
    return ApiSecurityEvent(
        event_id=incident_id,
        timestamp=datetime.now(timezone.utc),
        network=NetworkInfo(
            source_ip=source_ip,
            user_agent="ThreatGuard-SSRF-Lab",
        ),
        identity=IdentityInfo(
            user_id=attacker_user_id,
            session_id=f"lab-session-{attacker_user_id}",
            roles=["customer"],
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="POST",
            endpoint="/lab/fetch",
            query_params={},
            headers={
                "X-ThreatGuard-Lab": "SSRF",
            },
            body={
                "url": target_url,
            },
        ),
        response=ResponseInfo(
            status_code=target_response["status_code"],
            latency_ms=target_response["latency_ms"],
        ),
        resource=ResourceInfo(
            resource_type="internal_lab_service",
            resource_id="restricted",
            owner_id=attacker_user_id,
            is_sensitive=True,
        ),
    )


def _ssrf_detector_detected(processing_result) -> bool:
    return any(
        result.detector_id == "ssrf" and result.detected
        for result in processing_result.detector_results
    )


def enforce_lab_mitigation(processing_result) -> dict:
    recommended_action = processing_result.mitigation_action
    enforced = _ssrf_detector_detected(processing_result)

    return {
        "action": recommended_action,
        "enforced": enforced,
        "result": "REJECTED" if enforced else "ALLOWED",
        "description": (
            "ThreatGuard lab enforcement blocked the SSRF request to the restricted resource."
            if enforced
            else "ThreatGuard lab enforcement allowed the server-side request."
        ),
        "post_mitigation_response": {
            "status_code": 403 if enforced else 200,
            "body": (
                {
                    "error": "request_blocked",
                    "reason": "SSRF payload targeted a restricted localhost resource",
                }
                if enforced
                else {
                    "status": "allowed",
                }
            ),
        },
    }


def run_ssrf_attack_lab(source_ip: str = "127.0.0.1") -> dict:
    incident_id = f"LAB-SSRF-{uuid4().hex[:10]}"
    attacker_user_id = "user_101"
    target_url = INTERNAL_RESTRICTED_URL

    timestamps = {
        "ATTACKING": datetime.now(timezone.utc).isoformat(),
    }

    target_response = vulnerable_ssrf_fetch(target_url)
    timestamps["IMPACT_OBSERVED"] = datetime.now(timezone.utc).isoformat()

    event = build_ssrf_event(
        incident_id=incident_id,
        attacker_user_id=attacker_user_id,
        target_url=target_url,
        target_response=target_response,
        source_ip=source_ip,
    )

    processor = EventProcessor()
    processing_result = processor.process(event)

    timestamps["DETECTED"] = datetime.now(timezone.utc).isoformat()
    timestamps["MITIGATING"] = datetime.now(timezone.utc).isoformat()

    mitigation = enforce_lab_mitigation(processing_result)

    timestamps["MITIGATED"] = datetime.now(timezone.utc).isoformat()
    timestamps[mitigation["result"]] = timestamps["MITIGATED"]

    incident = {
        "incident_id": incident_id,
        "classification": CLASSIFICATION,
        "attack": {
            "name": "SSRF",
            "attacker": attacker_user_id,
            "source_ip": source_ip,
            "authentication": "Authenticated",
            "target_endpoint": "/lab/fetch",
            "method": "POST",
            "payload": {
                "url": target_url,
            },
            "attacker_request": "POST /lab/fetch",
            "request": {
                "method": "POST",
                "endpoint": "/lab/fetch",
                "body": {
                    "url": target_url,
                },
            },
        },
        "impact": {
            "observed": target_response["restricted_resource_reached"],
            "description": target_response["description"],
            "target_response_before_mitigation": target_response,
        },
        "detection": {
            "method": "existing_ssrf_detector",
            "detected": processing_result.risk_assessment.threat_detected,
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
