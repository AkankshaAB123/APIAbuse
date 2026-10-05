"""
Telemetry builders for the ThreatGuard Windows Endpoint Agent.

Constructs ``ApiSecurityEvent`` payloads that conform to the existing
backend schema (``backend/schemas/api_security_event.py``).  The
``domain`` field is set to ``"ENDPOINT"`` to distinguish endpoint events
from API-gateway events.

Schema reference (backend/schemas/api_security_event.py):
  NetworkInfo   : source_ip (required); user_agent, destination_ip, source_port,
                  destination_port, protocol, bytes, packets, connection_status (optional)
  IdentityInfo  : user_id, session_id (optional); roles (list); is_authenticated (bool)
  RequestInfo   : method, endpoint (required); path_params, query_params, headers, body (optional)
  ResponseInfo  : status_code (required); latency_ms (optional)
  ResourceInfo  : resource_type, resource_id, owner_id (optional); is_sensitive (bool)
  EndpointInfo  : all fields optional — event_type, hostname, username, process_name,
                  process_id, parent_process, executable_path, command_line,
                  privilege_level, keyboard_hook, network_connection, elevated
"""
from __future__ import annotations

import datetime
import platform
import socket
import uuid

from agents.windows.device import get_device_id


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def _local_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def _get_username() -> str:
    import os
    return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def _base_event(event_type: str) -> dict:
    """Return a skeleton payload matching ApiSecurityEvent schema."""
    device_id = get_device_id()
    hostname = platform.node()
    username = _get_username()

    return {
        "schema_version": "1.0",
        "event_id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "domain": "ENDPOINT",
        # --- network (only source_ip is required) ---
        "network": {
            "source_ip": _local_ip(),
            "user_agent": f"ThreatGuard-WindowsAgent/1.0 ({hostname})",
        },
        # --- identity ---
        "identity": {
            "user_id": device_id,
            "session_id": str(uuid.uuid4()),
            "roles": ["DEVICE"],
            "is_authenticated": False,
        },
        # --- request (method + endpoint required) ---
        "request": {
            "method": "AGENT",
            "endpoint": f"/agent/{event_type}",
            "headers": {"X-Device-ID": device_id},
            "body": None,
        },
        # --- response (status_code required) ---
        "response": {
            "status_code": 200,
            "latency_ms": 0.0,
        },
        # --- endpoint-specific block (all optional) ---
        "endpoint": {
            "event_type": event_type,
            "hostname": hostname,
            "username": username,
            "process_name": "",
            "process_id": 0,
            "parent_process": "",
            "executable_path": "",
            "command_line": "",
            "privilege_level": "standard",
            "keyboard_hook": False,
            "network_connection": False,
            "elevated": False,
        },
    }


# ---------------------------------------------------------------------------
# Public builders
# ---------------------------------------------------------------------------

def build_heartbeat_event() -> dict:
    """Build a lightweight heartbeat event to signal agent liveness."""
    event = _base_event("heartbeat")
    event["endpoint"]["process_name"] = "threatguard-agent"
    event["endpoint"]["executable_path"] = "agents/windows/main.py"
    event["endpoint"]["command_line"] = "python -m agents.windows --once"
    return event


def build_demo_event() -> dict:
    """
    Build a synthetic high-risk event that simulates a suspicious
    PowerShell invocation (reverse-shell indicator).

    Used with ``--demo`` flag for integration testing.
    """
    event = _base_event("process_creation")
    ep = event["endpoint"]
    ep["process_name"] = "powershell.exe"
    ep["process_id"] = 4242
    ep["parent_process"] = "cmd.exe"
    ep["executable_path"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    # Base64-encoded payload — safe demonstration only
    ep["command_line"] = (
        "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="
    )
    ep["privilege_level"] = "elevated"
    ep["elevated"] = True
    ep["network_connection"] = True
    return event
