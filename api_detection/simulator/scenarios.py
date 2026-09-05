"""Small deterministic traffic scenarios; attack fixtures are added per detector."""

from dataclasses import replace

from ..contracts import (
    ApiSecurityEvent,
    EndpointInfo,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResourceInfo,
    ResponseInfo,
)


def normal_event(
    event_id: str = "evt-normal-001",
) -> ApiSecurityEvent:
    return ApiSecurityEvent(
        event_id=event_id,
        timestamp="2026-09-01T10:00:00Z",
        network=NetworkInfo(
            source_ip="192.168.1.10",
            user_agent="demo-client/1.0",
        ),
        identity=IdentityInfo(
            user_id="user_17",
            session_id="session-normal-001",
            roles=("customer",),
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="GET",
            endpoint="/api/orders/17",
        ),
        response=ResponseInfo(
            status_code=200,
            latency_ms=42,
        ),
        resource=ResourceInfo(
            resource_type="order",
            resource_id="17",
            owner_id="user_17",
        ),
    )


def bola_idor_event(
    event_id: str = "evt-bola-001",
) -> ApiSecurityEvent:
    """Authenticated user requests an order owned by a different user."""

    event = normal_event(event_id)

    return replace(
        event,
        request=RequestInfo(
            method="GET",
            endpoint="/api/orders/42",
        ),
        resource=ResourceInfo(
            resource_type="order",
            resource_id="42",
            owner_id="user_42",
            is_sensitive=True,
        ),
    )


def privilege_escalation_event(
    event_id: str = "evt-bfla-001",
) -> ApiSecurityEvent:
    """Customer account tries to access an administrator-only operation."""

    event = normal_event(event_id)

    return replace(
        event,
        request=RequestInfo(
            method="DELETE",
            endpoint="/api/admin/users/user_42",
        ),
        resource=ResourceInfo(
            resource_type="user",
            resource_id="user_42",
            owner_id="user_42",
            is_sensitive=True,
        ),
    )


def failed_login_event(
    event_id: str,
    username: str,
    source_ip: str = "192.168.1.77",
) -> ApiSecurityEvent:
    """A failed login event used to construct credential-attack histories."""

    return ApiSecurityEvent(
        event_id=event_id,
        timestamp="2026-09-01T10:00:00Z",
        network=NetworkInfo(
            source_ip=source_ip,
            user_agent="demo-client/1.0",
        ),
        identity=IdentityInfo(
            is_authenticated=False,
        ),
        request=RequestInfo(
            method="POST",
            endpoint="/api/auth/login",
            body={
                "username": username,
                "password": "incorrect-demo-password",
            },
        ),
        response=ResponseInfo(
            status_code=401,
            latency_ms=35,
        ),
    )


def successful_login_event(
    event_id: str = "evt-takeover-success",
    source_ip: str = "192.168.1.77",
) -> ApiSecurityEvent:
    """A successful login event used with preceding failed attempts."""

    return ApiSecurityEvent(
        event_id=event_id,
        timestamp="2026-09-01T10:01:00Z",
        network=NetworkInfo(
            source_ip=source_ip,
            user_agent="demo-client/1.0",
        ),
        identity=IdentityInfo(
            user_id="user_17",
            session_id="session-takeover-001",
            roles=("customer",),
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="POST",
            endpoint="/api/auth/login",
            body={
                "username": "user_17",
                "password": "valid-demo-password",
            },
        ),
        response=ResponseInfo(
            status_code=200,
            latency_ms=42,
        ),
    )


def sql_injection_event(
    event_id: str = "evt-sqli-001",
) -> ApiSecurityEvent:
    """Search request carrying a Boolean-tautology SQLi pattern."""

    event = normal_event(event_id)

    return replace(
        event,
        request=RequestInfo(
            method="GET",
            endpoint="/api/products/search",
            query_params={
                "query": "' OR 1=1 --",
            },
        ),
    )


def ssrf_event(
    event_id: str = "evt-ssrf-001",
) -> ApiSecurityEvent:
    """Webhook request attempting to reach a cloud metadata address."""

    event = normal_event(event_id)

    return replace(
        event,
        request=RequestInfo(
            method="POST",
            endpoint="/api/integrations/webhooks",
            body={
                "callback_url": (
                    "http://169.254.169.254/latest/meta-data/"
                ),
            },
        ),
    )


def resource_exhaustion_event(
    event_id: str = "evt-resource-exhaustion-001",
    source_ip: str = "192.168.1.88",
) -> ApiSecurityEvent:
    """A request used to simulate repeated high-volume API traffic."""

    return ApiSecurityEvent(
        event_id=event_id,
        timestamp="2026-09-01T10:00:00Z",
        network=NetworkInfo(
            source_ip=source_ip,
            user_agent="demo-client/1.0",
        ),
        identity=IdentityInfo(
            user_id="user_17",
            session_id="session-resource-001",
            roles=("customer",),
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="GET",
            endpoint="/api/reports/export",
        ),
        response=ResponseInfo(
            status_code=200,
            latency_ms=150,
        ),
    )


def business_flow_abuse_event(
    event_id: str = "evt-business-flow-abuse-001",
) -> ApiSecurityEvent:
    """
    An authenticated user performs a sensitive business operation.
    Multiple events can be used to simulate repeated abuse.
    """

    return ApiSecurityEvent(
        event_id=event_id,
        timestamp="2026-09-01T10:00:00Z",
        network=NetworkInfo(
            source_ip="192.168.1.90",
            user_agent="demo-client/1.0",
        ),
        identity=IdentityInfo(
            user_id="user_17",
            session_id="session-business-flow-001",
            roles=("customer",),
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="POST",
            endpoint="/api/orders",
            body={
                "product_id": "product_42",
                "quantity": 1,
            },
        ),
        response=ResponseInfo(
            status_code=201,
            latency_ms=120,
        ),
        resource=ResourceInfo(
            resource_type="order",
            resource_id=None,
            owner_id="user_17",
            is_sensitive=True,
        ),
    )
def endpoint_enumeration_event(
    event_id: str = "evt-endpoint-enumeration-001",
    endpoint: str = "/api/users",
    source_ip: str = "192.168.1.95",
) -> ApiSecurityEvent:
    """
    Event used to simulate a client accessing many
    different API endpoints.
    """

    return ApiSecurityEvent(
        event_id=event_id,
        timestamp="2026-09-01T10:00:00Z",
        network=NetworkInfo(
            source_ip=source_ip,
            user_agent="demo-client/1.0",
        ),
        identity=IdentityInfo(
            user_id="user_17",
            session_id="session-enumeration-001",
            roles=("customer",),
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="GET",
            endpoint=endpoint,
        ),
        response=ResponseInfo(
            status_code=404,
            latency_ms=40,
        ),
    )
def ddos_event(
    event_id: str = "evt-ddos-001",
    source_ip: str = "192.0.2.5",
) -> ApiSecurityEvent:
    """
    Synthetic event used with recent_events to simulate
    distributed high-volume traffic.

    This function creates telemetry only. It does not
    generate real network traffic.
    """

    return ApiSecurityEvent(
        event_id=event_id,
        timestamp="2026-09-01T10:00:00Z",
        network=NetworkInfo(
            source_ip=source_ip,
            destination_ip="198.51.100.10",
            destination_port=443,
            protocol="TCP",
            bytes=512,
            packets=4,
            connection_status="success",
        ),
        identity=IdentityInfo(
            user_id="synthetic-user",
            session_id="synthetic-ddos-session",
            roles=("customer",),
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="GET",
            endpoint="/api/demo",
        ),
        response=ResponseInfo(
            status_code=200,
            latency_ms=25,
        ),
    )


def dos_flooding_event(
    event_id: str = "evt-dos-flooding-001",
) -> ApiSecurityEvent:
    """
    Synthetic event used with repeated recent_events to simulate
    high-volume traffic from one source to one destination.

    This function creates telemetry only.
    """

    return ApiSecurityEvent(
        event_id=event_id,
        timestamp="2026-09-01T10:00:00Z",
        network=NetworkInfo(
            source_ip="192.0.2.20",
            destination_ip="198.51.100.20",
            destination_port=443,
            protocol="TCP",
            bytes=512,
            packets=4,
            connection_status="success",
        ),
        identity=IdentityInfo(
            user_id="synthetic-user",
            session_id="synthetic-dos-session",
            roles=("customer",),
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="GET",
            endpoint="/api/demo",
        ),
        response=ResponseInfo(
            status_code=200,
            latency_ms=20,
        ),
    )


def port_scanning_event(
    event_id: str = "evt-port-scan-001",
    destination_port: int = 1000,
) -> ApiSecurityEvent:
    """
    Synthetic network telemetry used with recent_events to simulate
    contact with many destination ports.

    This function does not perform a real port scan.
    """

    return ApiSecurityEvent(
        event_id=event_id,
        timestamp="2026-09-01T10:00:00Z",
        network=NetworkInfo(
            source_ip="192.0.2.30",
            destination_ip="198.51.100.30",
            destination_port=destination_port,
            protocol="TCP",
            bytes=64,
            packets=1,
            connection_status="rejected",
        ),
        identity=IdentityInfo(
            user_id="synthetic-user",
            session_id="synthetic-port-scan-session",
            roles=("customer",),
            is_authenticated=True,
        ),
        request=RequestInfo(
            method="GET",
            endpoint="/api/network-probe",
        ),
        response=ResponseInfo(
            status_code=403,
            latency_ms=10,
        ),
    )


def network_brute_force_event(
    event_id: str = "evt-network-brute-force-001",
) -> ApiSecurityEvent:
    """
    Synthetic failed network connection telemetry used with
    recent_events to simulate repeated connection failures.

    This function does not perform real authentication attempts.
    """

    return ApiSecurityEvent(
        event_id=event_id,
        timestamp="2026-09-01T10:00:00Z",
        network=NetworkInfo(
            source_ip="192.0.2.40",
            destination_ip="198.51.100.40",
            destination_port=22,
            protocol="TCP",
            bytes=64,
            packets=1,
            connection_status="failed",
        ),
        identity=IdentityInfo(
            user_id="synthetic-user",
            session_id="synthetic-brute-force-session",
            roles=("customer",),
            is_authenticated=False,
        ),
        request=RequestInfo(
            method="GET",
            endpoint="/api/network-auth",
        ),
        response=ResponseInfo(
            status_code=401,
            latency_ms=15,
        ),
    )


def keylogging_event(
    event_id: str = "evt-keylogging-001",
) -> ApiSecurityEvent:
    """
    Synthetic endpoint telemetry indicating that a keyboard hook
    was observed.

    This does not install or interact with a real keylogger.
    """

    event = normal_event(event_id)

    return replace(
        event,
        endpoint=EndpointInfo(
            event_type="keyboard_hook_observed",
            hostname="demo-host-01",
            username="user_17",
            process_name="demo-input-service.exe",
            process_id=4120,
            parent_process="explorer.exe",
            executable_path="C:\\Demo\\demo-input-service.exe",
            command_line="demo-input-service.exe",
            privilege_level="user",
            keyboard_hook=True,
            network_connection=False,
            elevated=False,
        ),
    )


def suspicious_process_execution_event(
    event_id: str = "evt-suspicious-process-001",
) -> ApiSecurityEvent:
    """
    Synthetic endpoint telemetry indicating suspicious process
    execution.

    No process is actually launched.
    """

    event = normal_event(event_id)

    return replace(
        event,
        endpoint=EndpointInfo(
            event_type="process_execution",
            hostname="demo-host-02",
            username="user_17",
            process_name="powershell.exe",
            process_id=4180,
            parent_process="explorer.exe",
            executable_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -EncodedCommand SYNTHETIC_DEMO",
            privilege_level="user",
            keyboard_hook=False,
            network_connection=False,
            elevated=False,
        ),
    )


def reverse_shell_event(
    event_id: str = "evt-reverse-shell-001",
) -> ApiSecurityEvent:
    """
    Synthetic endpoint telemetry containing reverse-shell-like
    signals.

    No shell or network connection is actually created.
    """

    event = normal_event(event_id)

    return replace(
        event,
        endpoint=EndpointInfo(
            event_type="process_network_activity",
            hostname="demo-host-03",
            username="user_17",
            process_name="bash",
            process_id=4250,
            parent_process="systemd",
            executable_path="/bin/bash",
            command_line="bash -i SYNTHETIC_DEMO",
            privilege_level="user",
            keyboard_hook=False,
            network_connection=True,
            elevated=False,
        ),
    )


def endpoint_privilege_escalation_event(
    event_id: str = "evt-endpoint-privilege-escalation-001",
) -> ApiSecurityEvent:
    """
    Synthetic endpoint telemetry containing privilege-escalation
    indicators.

    No privileges are actually changed and no command is executed.
    """

    event = normal_event(event_id)

    return replace(
        event,
        endpoint=EndpointInfo(
            event_type="privilege_change",
            hostname="demo-host-04",
            username="user_17",
            process_name="demo-admin-helper.exe",
            process_id=4320,
            parent_process="explorer.exe",
            executable_path="C:\\Demo\\demo-admin-helper.exe",
            command_line="sudo SYNTHETIC_DEMO",
            privilege_level="root",
            keyboard_hook=False,
            network_connection=False,
            elevated=True,
        ),
    )
