"""Shared, dependency-free features that detectors can reuse."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Sequence

from ..contracts import ApiSecurityEvent


@dataclass(frozen=True)
class BehaviourFeatures:
    recent_request_count: int
    unique_endpoint_count: int
    failed_auth_count: int
    same_ip_request_count: int


def extract_behaviour_features(
    event: ApiSecurityEvent, recent_events: Sequence[ApiSecurityEvent]
) -> BehaviourFeatures:
    """Derive basic history-aware signals without deciding whether it is an attack."""
    all_events = [*recent_events, event]
    return BehaviourFeatures(
        recent_request_count=len(all_events),
        unique_endpoint_count=len({item.request.endpoint for item in all_events}),
        failed_auth_count=sum(
            item.response.status_code in {401, 403} for item in all_events
        ),
        same_ip_request_count=sum(
            item.network.source_ip == event.network.source_ip for item in all_events
        ),
    )
