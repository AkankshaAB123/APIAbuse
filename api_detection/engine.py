"""Single integration entry point for all API-security detectors."""

from __future__ import annotations

from collections.abc import Sequence

from .contracts import ApiSecurityEvent, DetectorResult
from .detectors import detect_bola_idor


def run_all_detectors(
    event: ApiSecurityEvent, recent_events: Sequence[ApiSecurityEvent] = ()
) -> list[DetectorResult]:
    """Run registered detectors against one event and its relevant history.

    Detectors are added here one at a time as they are implemented. Keeping the
    public entry point stable means the backend integration will not change.
    """
    return [detect_bola_idor(event, recent_events)]
