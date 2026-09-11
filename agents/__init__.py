"""Device Agents package for Intelligent Cloud IDS.

Provides standalone agents and client transport for transmitting security telemetry
to the central FastAPI backend.
"""

from agents.agent_client import AgentClient, AgentResponse

__all__ = ["AgentClient", "AgentResponse"]
