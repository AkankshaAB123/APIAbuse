from datetime import datetime, timezone
from time import perf_counter
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


LAB_RESOURCES = {
    "101": {
        "resource_id": "101",
        "owner_id": "user_101",
        "resource_type": "profile",
        "display_name": "User 101 Demo Profile",
        "data": {
            "email": "user101@example.test",
            "plan": "standard",
            "balance": 120,
        },
        "is_sensitive": True,
    },
    "202": {
        "resource_id": "202",
        "owner_id": "user_202",
        "resource_type": "profile",
        "display_name": "User 202 Demo Profile",
        "data": {
            "email": "user202@example.test",
            "plan": "premium",
            "balance": 950,
        },
        "is_sensitive": True,
    },
}


CLASSIFICATION = {
    "level1": "API",
    "level2": "Authorization",
    "level3": "BOLA / IDOR",
}


def get_lab_resource(resource_id: str) -> dict | None:
    resource = LAB_RESOURCES.get(resource_id)

    if resource is None:
        return None

    return {
        "resource_id": resource["resource_id"],
        "owner_id": resource["owner_id"],
        "resource_type": resource["resource_type"],
        "display_name": resource["display_name"],
        "is_sensitive": resource["is_sensitive"],
    }


def vulnerable_resource_request(
    requester_user_id: str,
    requested_resource_id: str,
) -> dict:
    """
    Deliberately vulnerable lab target.

    It returns the requested synthetic resource without first
    validating ownership. The monitoring layer observes that
    behavior and converts it into the existing security event.
    """

    resource = LAB_RESOURCES.get(requested_resource_id)

    if resource is None:
        return {
            "status_code": 404,
            "body": {
                "error": "resource_not_found",
            },
            "latency_ms": 12,
            "unauthorized_access": False,
        }

    unauthorized_access = requester_user_id != resource["owner_id"]

    return {
        "status_code": 200,
        "body": {
            "resource_id": resource["resource_id"],
            "owner_id": resource["owner_id"],
            "display_name": resource["display_name"],
            "data": resource["data"],
        },
        "latency_ms": 18,
        "unauthorized_access": unauthorized_access,
        "description": (
            "The vulnerable lab target returned a resource owned by "
            f"{resource['owner_id']} to requester {requester_user_id}."
            if unauthorized_access
            else "The requester accessed their own synthetic resource."
        ),
    }


def build_bola_event(
    incident_id: str,
    attacker_user_id: str,
    requested_resource_id: str,
    target_response: dict,
    source_ip: str = "127.0.0.1",
) -> ApiSecurityEvent:
    resource = LAB_RESOURCES[requested_resource_id]

    return ApiSecurityEvent(
        event_id=incident_id,
        timestamp=datetime.now(timezone.utc),
        network=NetworkInfo(
            source_ip=source_ip,
            user_agent="ThreatGuard-BOLA-Lab",
        ),
        identity=IdentityInfo(
            user_id=attacker_user_id,
            session_id=f"lab-session-{attacker_user_id}",
            roles=["customer"],
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="GET",
            endpoint=f"/lab/resources/{requested_resource_id}",
            path_params={
                "resource_id": requested_resource_id,
            },
            query_params={},
            headers={
                "X-ThreatGuard-Lab": "BOLA",
            },
            body=None,
        ),
        response=ResponseInfo(
            status_code=target_response["status_code"],
            latency_ms=target_response["latency_ms"],
        ),
        resource=ResourceInfo(
            resource_type=resource["resource_type"],
            resource_id=resource["resource_id"],
            owner_id=resource["owner_id"],
            is_sensitive=resource["is_sensitive"],
        ),
    )


def enforce_lab_mitigation(processing_result) -> dict:
    action = processing_result.mitigation_action
    enforced = action == "BLOCK"

    return {
        "action": action,
        "enforced": enforced,
        "result": "REJECTED" if enforced else "ALLOWED",
        "description": (
            "ThreatGuard lab enforcement rejected the unauthorized resource response."
            if enforced
            else "ThreatGuard lab enforcement allowed the request."
        ),
        "post_mitigation_response": {
            "status_code": 403 if enforced else 200,
            "body": (
                {
                    "error": "request_blocked",
                    "reason": "BOLA / IDOR owner mismatch detected",
                }
                if enforced
                else {
                    "status": "allowed",
                }
            ),
        },
    }


def run_bola_attack_lab(source_ip: str = "127.0.0.1") -> dict:
    incident_id = f"LAB-BOLA-{uuid4().hex[:10]}"
    attacker_user_id = "user_101"
    target_user_id = "user_202"
    requested_resource_id = "202"

    timestamps = {
        "ATTACKING": datetime.now(timezone.utc).isoformat(),
    }

    started = perf_counter()
    target_response = vulnerable_resource_request(
        requester_user_id=attacker_user_id,
        requested_resource_id=requested_resource_id,
    )
    target_response["latency_ms"] = round(
        (perf_counter() - started) * 1000,
        2,
    )

    timestamps["IMPACT_OBSERVED"] = datetime.now(timezone.utc).isoformat()

    event = build_bola_event(
        incident_id=incident_id,
        attacker_user_id=attacker_user_id,
        requested_resource_id=requested_resource_id,
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
            "name": "BOLA / IDOR",
            "attacker": attacker_user_id,
            "source_ip": source_ip,
            "authentication": "Authenticated",
            "target_user": target_user_id,
            "requested_resource": requested_resource_id,
            "target_endpoint": f"/lab/resources/{requested_resource_id}",
            "method": "GET",
            "request": {
                "method": "GET",
                "endpoint": f"/lab/resources/{requested_resource_id}",
                "path_params": {
                    "resource_id": requested_resource_id,
                },
                "query_params": {
                    "requester": attacker_user_id,
                },
            },
        },
        "impact": {
            "observed": target_response["unauthorized_access"],
            "description": target_response["description"],
            "target_response_before_mitigation": target_response,
        },
        "detection": {
            "method": "existing_bola_detector",
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
