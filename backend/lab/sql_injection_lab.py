import sqlite3
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


CLASSIFICATION = {
    "level1": "API",
    "level2": "Injection",
    "level3": "SQL Injection",
}

LAB_PRODUCTS = (
    (1, "Laptop", "electronics", 1200),
    (2, "Phone", "electronics", 800),
    (3, "SOC Analyst Guide", "books", 45),
    (4, "Admin Audit Token", "internal", 0),
)

MALICIOUS_SEARCH = "' OR 1=1 --"


def _create_lab_database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price INTEGER NOT NULL
        )
        """
    )
    connection.executemany(
        "INSERT INTO products (id, name, category, price) VALUES (?, ?, ?, ?)",
        LAB_PRODUCTS,
    )
    return connection


def _safe_baseline_count(search: str) -> int:
    connection = _create_lab_database()
    try:
        rows = connection.execute(
            "SELECT id FROM products WHERE name LIKE ?",
            (f"%{search}%",),
        ).fetchall()
        return len(rows)
    finally:
        connection.close()


def vulnerable_product_search(search: str) -> dict:
    """
    Deliberately vulnerable SQLi lab target.

    The query is executed only against an in-memory SQLite database populated
    with synthetic rows. This demonstrates query manipulation without touching
    any real database or external system.
    """

    connection = _create_lab_database()
    vulnerable_query = (
        "SELECT id, name, category, price FROM products "
        f"WHERE name LIKE '%{search}%'"
    )
    started = perf_counter()

    try:
        rows = connection.execute(vulnerable_query).fetchall()
        latency_ms = round((perf_counter() - started) * 1000, 2)
        safe_count = _safe_baseline_count(search)
        returned_rows = [dict(row) for row in rows]
        query_manipulated = len(returned_rows) > safe_count

        return {
            "status_code": 200,
            "body": {
                "search": search,
                "rows": returned_rows,
                "row_count": len(returned_rows),
            },
            "latency_ms": latency_ms,
            "executed_query": vulnerable_query,
            "safe_parameterized_row_count": safe_count,
            "vulnerable_row_count": len(returned_rows),
            "query_manipulated": query_manipulated,
            "description": (
                "The vulnerable lab target returned unexpected rows because "
                "the SQL input changed the query logic."
                if query_manipulated
                else "The vulnerable lab target returned only matching rows."
            ),
        }
    except sqlite3.Error as exc:
        latency_ms = round((perf_counter() - started) * 1000, 2)
        return {
            "status_code": 500,
            "body": {
                "error": "lab_query_error",
                "message": str(exc),
            },
            "latency_ms": latency_ms,
            "executed_query": vulnerable_query,
            "safe_parameterized_row_count": _safe_baseline_count(search),
            "vulnerable_row_count": 0,
            "query_manipulated": True,
            "description": (
                "The vulnerable lab target produced a SQL error after "
                "processing the injected input."
            ),
        }
    finally:
        connection.close()


def build_sql_injection_event(
    incident_id: str,
    attacker_user_id: str,
    search: str,
    target_response: dict,
    source_ip: str = "127.0.0.1",
) -> ApiSecurityEvent:
    return ApiSecurityEvent(
        event_id=incident_id,
        timestamp=datetime.now(timezone.utc),
        network=NetworkInfo(
            source_ip=source_ip,
            user_agent="ThreatGuard-SQLi-Lab",
        ),
        identity=IdentityInfo(
            user_id=attacker_user_id,
            session_id=f"lab-session-{attacker_user_id}",
            roles=["customer"],
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="GET",
            endpoint="/lab/products/search",
            query_params={
                "query": search,
            },
            headers={
                "X-ThreatGuard-Lab": "SQL_INJECTION",
            },
            body=None,
        ),
        response=ResponseInfo(
            status_code=target_response["status_code"],
            latency_ms=target_response["latency_ms"],
        ),
        resource=ResourceInfo(
            resource_type="product_catalog",
            resource_id="lab-products",
            owner_id=attacker_user_id,
            is_sensitive=True,
        ),
    )


def _sql_detector_detected(processing_result) -> bool:
    return any(
        result.detector_id == "sql_injection" and result.detected
        for result in processing_result.detector_results
    )


def enforce_lab_mitigation(processing_result) -> dict:
    recommended_action = processing_result.mitigation_action
    detected = _sql_detector_detected(processing_result)
    enforced = detected

    return {
        "action": recommended_action,
        "enforced": enforced,
        "result": "REJECTED" if enforced else "ALLOWED",
        "description": (
            "ThreatGuard lab enforcement rejected the injected search request."
            if enforced
            else "ThreatGuard lab enforcement allowed the search request."
        ),
        "post_mitigation_response": {
            "status_code": 403 if enforced else 200,
            "body": (
                {
                    "error": "request_blocked",
                    "reason": "SQL injection payload detected in query parameter",
                }
                if enforced
                else {
                    "status": "allowed",
                }
            ),
        },
    }


def run_sql_injection_attack_lab(source_ip: str = "127.0.0.1") -> dict:
    incident_id = f"LAB-SQLI-{uuid4().hex[:10]}"
    attacker_user_id = "user_101"
    search = MALICIOUS_SEARCH

    timestamps = {
        "ATTACKING": datetime.now(timezone.utc).isoformat(),
    }

    target_response = vulnerable_product_search(search)
    timestamps["IMPACT_OBSERVED"] = datetime.now(timezone.utc).isoformat()

    event = build_sql_injection_event(
        incident_id=incident_id,
        attacker_user_id=attacker_user_id,
        search=search,
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
            "name": "SQL Injection",
            "attacker": attacker_user_id,
            "source_ip": source_ip,
            "authentication": "Authenticated",
            "target_endpoint": "/lab/products/search",
            "method": "GET",
            "query_param": "query",
            "payload": search,
            "attacker_request": f"GET /lab/products/search?query={search}",
            "request": {
                "method": "GET",
                "endpoint": "/lab/products/search",
                "query_params": {
                    "query": search,
                },
            },
        },
        "impact": {
            "observed": target_response["query_manipulated"],
            "description": target_response["description"],
            "target_response_before_mitigation": target_response,
        },
        "detection": {
            "method": "existing_sql_injection_detector",
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
