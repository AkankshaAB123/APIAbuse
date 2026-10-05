"""Rule-based SQL injection detection for API request input."""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterable, Sequence
from typing import Any

from ..contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)
from ..rules.sql_injection import SQL_INJECTION_PATTERNS, SQL_INJECTION_RULE_VERSION

DETECTOR_ID = "sql_injection"


def normalize_value(value: str) -> str:
    """Safely normalize request value using repeated URL percent-decoding and whitespace collapsing."""
    if not isinstance(value, str):
        value = str(value)

    current = value
    for _ in range(3):
        try:
            decoded = urllib.parse.unquote(current)
        except Exception:
            break
        if decoded == current:
            break
        current = decoded

    current = current.replace("\x00", "")
    return re.sub(r"\s+", " ", current).strip()


def detect_sql_injection(
    event: ApiSecurityEvent, recent_events: Sequence[ApiSecurityEvent] = ()
) -> DetectorResult:
    """Inspect incoming API parameter values for high-confidence SQLi signatures."""
    del recent_events
    for field_name, raw_value in _request_values(event):
        normalized = normalize_value(raw_value)
        for code, pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, normalized, flags=re.IGNORECASE) or re.search(
                pattern, raw_value, flags=re.IGNORECASE
            ):
                return DetectorResult(
                    event_id=event.event_id,
                    detector_id=DETECTOR_ID,
                    detected=True,
                    attack_type=AttackType.SQL_INJECTION,
                    confidence=0.96,
                    severity=Severity.HIGH,
                    evidence=(
                        Evidence(
                            code=code,
                            message=f"Suspicious SQL injection pattern in {field_name}",
                        ),
                    ),
                    metadata={"rule_version": SQL_INJECTION_RULE_VERSION, "window_seconds": 0},
                )

    return DetectorResult(
        event_id=event.event_id,
        detector_id=DETECTOR_ID,
        detected=False,
        attack_type=None,
        confidence=0.0,
        severity=Severity.LOW,
        metadata={"rule_version": SQL_INJECTION_RULE_VERSION, "window_seconds": 0},
    )


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
