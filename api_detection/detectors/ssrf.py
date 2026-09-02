"""Detect SSRF-style URLs in API request input."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from typing import Any
from urllib.parse import urlparse

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)
from ..rules.ssrf import CLOUD_METADATA_HOSTS, SSRF_RULE_VERSION, SSRF_URL_FIELD_HINTS

DETECTOR_ID = "ssrf"


def detect_ssrf(
    event: ApiSecurityEvent, recent_events: Sequence[ApiSecurityEvent] = ()
) -> DetectorResult:
    """Flag URL-like request values targeting internal or metadata hosts."""
    del recent_events
    for field_name, value in _request_values(event):
        if not _is_url_candidate(field_name, value):
            continue
        host = urlparse(value).hostname
        if not host:
            continue
        code = _host_risk_code(host)
        if code:
            return DetectorResult(
                event_id=event.event_id,
                detector_id=DETECTOR_ID,
                detected=True,
                attack_type=AttackType.SSRF,
                confidence=0.95,
                severity=Severity.HIGH,
                evidence=(
                    Evidence(
                        code=code,
                        message=f"Request field {field_name} targets restricted host {host}",
                    ),
                ),
                metadata={"rule_version": SSRF_RULE_VERSION, "window_seconds": 0},
            )

    return DetectorResult(
        event_id=event.event_id,
        detector_id=DETECTOR_ID,
        detected=False,
        attack_type=None,
        confidence=0.0,
        severity=Severity.LOW,
        metadata={"rule_version": SSRF_RULE_VERSION, "window_seconds": 0},
    )


def _is_url_candidate(field_name: str, value: str) -> bool:
    leaf_name = field_name.rsplit(".", maxsplit=1)[-1].lower()
    return value.startswith(("http://", "https://")) or leaf_name in SSRF_URL_FIELD_HINTS


def _host_risk_code(host: str) -> str | None:
    normalized_host = host.lower().rstrip(".")
    if normalized_host in CLOUD_METADATA_HOSTS:
        return "CLOUD_METADATA_TARGET"
    if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
        return "LOOPBACK_TARGET"
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        return None
    if address.is_loopback:
        return "LOOPBACK_TARGET"
    if address.is_private or address.is_link_local:
        return "PRIVATE_NETWORK_TARGET"
    return None


def _request_values(event: ApiSecurityEvent) -> Iterable[tuple[str, str]]:
    yield from _flatten("path_params", event.request.path_params)
    yield from _flatten("query_params", event.request.query_params)
    yield from _flatten("body", event.request.body)


def _flatten(field_name: str, value: Any) -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _flatten(f"{field_name}.{key}", item)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _flatten(f"{field_name}[{index}]", item)
    elif value is not None:
        yield field_name, str(value)
