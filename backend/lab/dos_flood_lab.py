from datetime import datetime, timedelta, timezone
import json
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
    "level1": "API",
    "level2": "Availability",
    "level3": "DoS / API Flooding / Resource Exhaustion",
}

FLOOD_TARGET_PATH = "/lab/flood-target"
FLOOD_TARGET_URL = "http://127.0.0.1:8000/lab/flood-target"
LAB_SOURCE = "127.0.0.1"
LAB_ATTACKER = "lab-flood-attacker"
BURST_REQUEST_COUNT = 30
POST_MITIGATION_PROBE_COUNT = 5
RESOURCE_EXHAUSTION_THRESHOLD = 10

_RATE_LIMITED_SOURCES: set[str] = set()
_TARGET_REQUEST_COUNTER = 0


def reset_flood_lab_state() -> None:
    global _TARGET_REQUEST_COUNTER
    _RATE_LIMITED_SOURCES.clear()
    _TARGET_REQUEST_COUNTER = 0


def flood_target_request(source: str = LAB_SOURCE) -> dict:
    global _TARGET_REQUEST_COUNTER

    _TARGET_REQUEST_COUNTER += 1

    if source in _RATE_LIMITED_SOURCES:
        return {
            "status_code": 429,
            "body": {
                "status": "rate_limited",
                "message": "Controlled lab rate limiter rejected this request.",
                "target_request_number": _TARGET_REQUEST_COUNTER,
            },
            "accepted": False,
            "latency_ms": 2,
        }

    return {
        "status_code": 200,
        "body": {
            "status": "accepted",
            "message": "Controlled lab target accepted the request.",
            "target_request_number": _TARGET_REQUEST_COUNTER,
        },
        "accepted": True,
        "latency_ms": 4,
    }


def _send_target_request(source: str) -> dict:
    request = Request(
        f"{FLOOD_TARGET_URL}?source={source}",
        headers={
            "User-Agent": "ThreatGuard-Flood-Lab-Attacker",
        },
    )

    started = perf_counter()

    try:
        with urlopen(request, timeout=5) as response:
            latency_ms = round((perf_counter() - started) * 1000, 2)
            body = json.loads(response.read().decode("utf-8"))
            return {
                "status_code": body.get("status_code", response.status),
                "accepted": body.get("accepted", response.status < 400),
                "latency_ms": latency_ms,
            }
    except HTTPError as exc:
        latency_ms = round((perf_counter() - started) * 1000, 2)
        body = json.loads(exc.read().decode("utf-8"))
        return {
            "status_code": body.get("status_code", exc.code),
            "accepted": body.get("accepted", False),
            "latency_ms": latency_ms,
        }
    except URLError as exc:
        latency_ms = round((perf_counter() - started) * 1000, 2)
        return {
            "status_code": 0,
            "accepted": False,
            "latency_ms": latency_ms,
            "error": str(exc),
        }


def build_flood_event(
    event_id: str,
    timestamp: datetime,
    status_code: int,
    latency_ms: float,
    source: str = LAB_SOURCE,
) -> ApiSecurityEvent:
    return ApiSecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        network=NetworkInfo(
            source_ip=source,
            user_agent="ThreatGuard-Flood-Lab-Attacker",
        ),
        identity=IdentityInfo(
            user_id=LAB_ATTACKER,
            session_id="lab-session-flood",
            roles=["customer"],
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="GET",
            endpoint=FLOOD_TARGET_PATH,
            query_params={
                "source": source,
            },
            headers={
                "X-ThreatGuard-Lab": "DOS_FLOODING",
            },
            body=None,
        ),
        response=ResponseInfo(
            status_code=status_code,
            latency_ms=latency_ms,
        ),
        resource=ResourceInfo(
            resource_type="api_endpoint",
            resource_id=FLOOD_TARGET_PATH,
            owner_id=LAB_ATTACKER,
            is_sensitive=False,
        ),
    )


def _persist_burst_telemetry(
    incident_id: str,
    source: str,
    responses: list[dict],
) -> None:
    started_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    documents = []

    for index, response in enumerate(responses[:-1], start=1):
        event = build_flood_event(
            event_id=f"{incident_id}-burst-{index:03d}",
            timestamp=started_at + timedelta(milliseconds=index * 100),
            status_code=response["status_code"],
            latency_ms=response["latency_ms"],
            source=source,
        )
        documents.append(event.model_dump())

    if documents:
        events_collection.insert_many(documents)


def _resource_exhaustion_detector(processing_result) -> dict | None:
    for result in processing_result.detector_results:
        if result.detector_id == "resource_exhaustion":
            return result.model_dump()
    return None


def enforce_lab_mitigation(processing_result) -> dict:
    recommended_action = processing_result.mitigation_action
    detector = _resource_exhaustion_detector(processing_result)
    enforced = bool(detector and detector["detected"])
    source = processing_result.source_ip

    if enforced:
        _RATE_LIMITED_SOURCES.add(source)

    post_mitigation_responses = [
        _send_target_request(source)
        for _ in range(POST_MITIGATION_PROBE_COUNT)
    ]
    rejected_count = sum(
        1 for response in post_mitigation_responses
        if response["status_code"] in {403, 429}
    )

    return {
        "action": recommended_action,
        "enforced": enforced,
        "result": "RATE_LIMITED" if enforced else "ALLOWED",
        "description": (
            "ThreatGuard lab enforcement rate-limited the flood source."
            if enforced
            else "ThreatGuard lab enforcement allowed the source."
        ),
        "post_mitigation_response": {
            "status_code": 429 if enforced else 200,
            "body": (
                {
                    "error": "request_rate_limited",
                    "reason": "API flooding threshold exceeded",
                }
                if enforced
                else {
                    "status": "allowed",
                }
            ),
        },
        "post_mitigation_probe_count": POST_MITIGATION_PROBE_COUNT,
        "post_mitigation_rejected": rejected_count,
        "post_mitigation_responses": post_mitigation_responses,
    }


def run_dos_flood_attack_lab(client_ip: str = "127.0.0.1") -> dict:
    reset_flood_lab_state()

    incident_id = f"LAB-FLOOD-{uuid4().hex[:10]}"
    source = f"127.0.0.{int(incident_id[-2:], 16) % 200 + 20}"
    timestamps = {
        "ATTACKING": datetime.now(timezone.utc).isoformat(),
    }

    started = perf_counter()
    burst_responses = [
        _send_target_request(source)
        for _ in range(BURST_REQUEST_COUNT)
    ]
    burst_duration_seconds = max(perf_counter() - started, 0.001)
    request_rate_per_second = round(
        len(burst_responses) / burst_duration_seconds,
        2,
    )
    accepted_before_mitigation = sum(
        1 for response in burst_responses
        if response["accepted"]
    )

    timestamps["IMPACT_OBSERVED"] = datetime.now(timezone.utc).isoformat()

    _persist_burst_telemetry(incident_id, source, burst_responses)

    final_response = burst_responses[-1]
    event = build_flood_event(
        event_id=incident_id,
        timestamp=datetime.now(timezone.utc),
        status_code=final_response["status_code"],
        latency_ms=final_response["latency_ms"],
        source=source,
    )

    processor = EventProcessor()
    processing_result = processor.process(event)

    timestamps["DETECTED"] = datetime.now(timezone.utc).isoformat()
    timestamps["MITIGATING"] = datetime.now(timezone.utc).isoformat()

    mitigation = enforce_lab_mitigation(processing_result)

    timestamps["MITIGATED"] = datetime.now(timezone.utc).isoformat()
    timestamps[mitigation["result"]] = timestamps["MITIGATED"]

    detector = _resource_exhaustion_detector(processing_result)

    incident = {
        "incident_id": incident_id,
        "classification": CLASSIFICATION,
        "attack": {
            "name": "DoS / API Flooding",
            "attacker": LAB_ATTACKER,
            "actual_client_ip": client_ip,
            "source_ip": source,
            "source_identity_type": "Synthetic loopback source used to isolate repeat lab runs",
            "authentication": "Unauthenticated / Synthetic traffic generator",
            "target_endpoint": FLOOD_TARGET_PATH,
            "method": "GET",
            "attacker_request": f"GET {FLOOD_TARGET_PATH}?source={source}",
            "request_count": BURST_REQUEST_COUNT,
            "request": {
                "method": "GET",
                "endpoint": FLOOD_TARGET_PATH,
                "query_params": {
                    "source": source,
                },
            },
        },
        "impact": {
            "observed": accepted_before_mitigation >= RESOURCE_EXHAUSTION_THRESHOLD,
            "description": (
                "The controlled lab target accepted a bounded burst of API requests "
                "before rate-limit enforcement."
            ),
            "target_response_before_mitigation": {
                "status_code": 200 if accepted_before_mitigation else 429,
                "total_requests": BURST_REQUEST_COUNT,
                "accepted_requests": accepted_before_mitigation,
                "rejected_requests": BURST_REQUEST_COUNT - accepted_before_mitigation,
                "duration_seconds": round(burst_duration_seconds, 3),
                "requests_per_second": request_rate_per_second,
                "requests_per_minute": round(request_rate_per_second * 60, 2),
                "baseline_requests": 1,
                "threshold": RESOURCE_EXHAUSTION_THRESHOLD,
                "sample_responses": burst_responses[:3],
            },
        },
        "detection": {
            "method": "existing_resource_exhaustion_detector",
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
