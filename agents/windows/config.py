"""
Configuration for the ThreatGuard Windows Endpoint Agent.

Reads settings from environment variables with sensible defaults.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class AgentConfig:
    """Holds all runtime configuration for the Windows agent."""

    backend_url: str = "http://127.0.0.1:8000"
    heartbeat_interval: int = 30          # seconds between heartbeats
    timeout: float = 8.0                  # HTTP request timeout in seconds
    queue_size: int = 50                  # max offline events buffered

    # Optional JWT token for authenticated endpoints (e.g., GET /threats)
    auth_token: str | None = None

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Construct config from environment variables."""
        return cls(
            backend_url=os.environ.get(
                "THREATGUARD_BACKEND_URL", "http://127.0.0.1:8000"
            ).rstrip("/"),
            heartbeat_interval=int(
                os.environ.get("THREATGUARD_HEARTBEAT_INTERVAL", "30")
            ),
            timeout=float(os.environ.get("THREATGUARD_TIMEOUT", "8.0")),
            queue_size=int(os.environ.get("THREATGUARD_QUEUE_SIZE", "50")),
            auth_token=os.environ.get("THREATGUARD_AUTH_TOKEN"),
        )
