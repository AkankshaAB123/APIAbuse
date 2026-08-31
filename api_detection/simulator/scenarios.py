"""Small deterministic traffic scenarios; attack fixtures are added per detector."""

from ..contracts import (
    ApiSecurityEvent,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResourceInfo,
    ResponseInfo,
)


def normal_event(event_id: str = "evt-normal-001") -> ApiSecurityEvent:
    return ApiSecurityEvent(
        event_id=event_id,
        timestamp="2026-09-01T10:00:00Z",
        network=NetworkInfo(source_ip="192.168.1.10", user_agent="demo-client/1.0"),
        identity=IdentityInfo(
            user_id="user_17",
            session_id="session-normal-001",
            roles=("customer",),
            is_authenticated=True,
        ),
        request=RequestInfo(method="GET", endpoint="/api/orders/17"),
        response=ResponseInfo(status_code=200, latency_ms=42),
        resource=ResourceInfo(
            resource_type="order", resource_id="17", owner_id="user_17"
        ),
    )
