# Detect SSRF-style URLs in API request input.

from __future__ import annotations

import ipaddress
import re
import urllib.parse
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
from ..rules.ssrf import (
    CLOUD_METADATA_HOSTS,
    RESTRICTED_PROTOCOLS,
    SSRF_RULE_VERSION,
    SSRF_URL_FIELD_HINTS,
)

DETECTOR_ID = "ssrf"


def detect_ssrf(event: ApiSecurityEvent, recent_events: Sequence[ApiSecurityEvent] = ()) -> DetectorResult:
    """Flag URL‑like request values targeting internal or restricted resources.

    The detector normalises the raw string, handles scheme‑less URLs for fields that are
    known to contain URLs, checks for dangerous protocols, and maps hosts to risk codes.
    """
    del recent_events  # Unused for this deterministic rule detector

    for field_name, raw_value in _request_values(event):
        if not _is_url_candidate(field_name, raw_value):
            continue

        # Normalise the value before parsing
        norm = _normalize_url(raw_value)
        parsed = urlparse(norm)
        scheme = parsed.scheme.lower()
        host = parsed.hostname

        # Restricted protocol detection (e.g., file://, gopher://, etc.)
        if scheme and scheme in RESTRICTED_PROTOCOLS:
            return DetectorResult(
                event_id=event.event_id,
                detector_id=DETECTOR_ID,
                detected=True,
                attack_type=AttackType.SSRF,
                confidence=0.95,
                severity=Severity.HIGH,
                evidence=(
                    Evidence(
                        code="RESTRICTED_PROTOCOL_TARGET",
                        message=f"Request field {field_name} uses restricted protocol {scheme}",
                    ),
                ),
                metadata={"rule_version": SSRF_RULE_VERSION, "window_seconds": 0},
            )

        if not host:
            continue

        code = _host_risk_code(host)
        if code:
            severity = Severity.CRITICAL if code == "CLOUD_METADATA_TARGET" else Severity.HIGH
            return DetectorResult(
                event_id=event.event_id,
                detector_id=DETECTOR_ID,
                detected=True,
                attack_type=AttackType.SSRF,
                confidence=0.95,
                severity=severity,
                evidence=(
                    Evidence(
                        code=code,
                        message=f"Request field {field_name} targets restricted host {host}",
                    ),
                ),
                metadata={"rule_version": SSRF_RULE_VERSION, "window_seconds": 0},
            )

    # Clean event – no SSRF detected
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
    """Determine whether *value* should be inspected for SSRF.

    A field is a candidate if it already looks like a URL (http/https) or the leaf
    name of the field is listed in :data:`SSRF_URL_FIELD_HINTS`.
    """
    leaf_name = field_name.rsplit(".", maxsplit=1)[-1].lower()
    return value.startswith(("http://", "https://")) or leaf_name in SSRF_URL_FIELD_HINTS


def _host_risk_code(host: str) -> str | None:
    """Return a risk code for *host* if it matches a known internal target.

    Checks cloud‑metadata hosts, localhost and IPv4/IPv6 loopback, private and link‑local networks.
    """
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
    """Yield (field_path, stringified value) for all request components."""
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


def _normalize_url(value: str) -> str:
    """Iteratively percent‑decode, strip null bytes and surrounding whitespace.

    * Up to three decoding passes handle double‑encoding.
    * Null bytes are removed.
    * Leading/trailing whitespace is stripped.
    * Scheme‑less strings are prefixed with ``//`` so ``urlparse`` can still extract a hostname.
    """
    cleaned = value.strip().replace("\x00", "")
    for _ in range(3):
        decoded = urllib.parse.unquote_plus(cleaned)
        if decoded == cleaned:
            break
        cleaned = decoded
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned) and not cleaned.startswith("//"):
        cleaned = f"//{cleaned}"
    return cleaned
