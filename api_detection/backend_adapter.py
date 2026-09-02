"""Compatibility boundary between Member 2 detectors and the backend schemas.

This module intentionally uses plain dictionaries at its public boundary. The
backend can pass its Pydantic ``ApiSecurityEvent`` directly, while this package
does not need to import or modify any Member 3 files.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .contracts import (
    ApiSecurityEvent,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResourceInfo,
    ResponseInfo,
)
from .engine import run_all_detectors


def adapt_backend_event(event: Any) -> ApiSecurityEvent:
    """Convert a backend Pydantic event or mapping to the detector event model."""
    payload = _as_mapping(event)
    network = _as_mapping(payload["network"])
    identity = _as_mapping(payload["identity"])
    request = _as_mapping(payload["request"])
    response = _as_mapping(payload["response"])
    resource = _as_mapping(payload["resource"])
    timestamp = payload["timestamp"]

    return ApiSecurityEvent(
        schema_version=str(payload.get("schema_version", "1.0")),
        event_id=str(payload["event_id"]),
        timestamp=timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp),
        network=NetworkInfo(
            source_ip=str(network["source_ip"]),
            user_agent=network.get("user_agent"),
        ),
        identity=IdentityInfo(
            user_id=identity.get("user_id"),
            session_id=identity.get("session_id"),
            roles=tuple(identity.get("roles", [])),
            is_authenticated=bool(identity.get("is_authenticated", False)),
        ),
        request=RequestInfo(
            method=str(request["method"]),
            endpoint=str(request["endpoint"]),
            path_params=dict(request.get("path_params", {})),
            query_params=dict(request.get("query_params", {})),
            headers=dict(request.get("headers", {})),
            body=request.get("body"),
        ),
        response=ResponseInfo(
            status_code=int(response["status_code"]),
            latency_ms=response.get("latency_ms"),
        ),
        resource=ResourceInfo(
            resource_type=resource.get("resource_type"),
            resource_id=resource.get("resource_id"),
            owner_id=resource.get("owner_id"),
            is_sensitive=bool(resource.get("is_sensitive", False)),
        ),
    )


def to_backend_detector_result(result: Any) -> dict[str, Any]:
    """Return the exact payload accepted by backend.schemas.DetectorResult."""
    payload = result.to_dict()
    metadata = dict(payload["metadata"])
    details = {
        key: value
        for key, value in metadata.items()
        if key not in {"rule_version", "window_seconds"}
    }
    payload["metadata"] = {
        "rule_version": metadata.get("rule_version", "1.0"),
        "window_seconds": metadata.get("window_seconds", 0),
        "details": details,
    }
    return payload


def run_for_backend(
    event: Any, recent_events: Sequence[Any] = ()
) -> list[dict[str, Any]]:
    """Run detectors using backend events and return backend-valid result payloads."""
    detector_event = adapt_backend_event(event)
    detector_history = [adapt_backend_event(item) for item in recent_events]
    return [
        to_backend_detector_result(result)
        for result in run_all_detectors(detector_event, detector_history)
    ]


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump()
    raise TypeError("Expected a mapping or a Pydantic model with model_dump()")
