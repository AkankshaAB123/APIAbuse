from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class NetworkInfo(BaseModel):
    source_ip: str
    user_agent: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    bytes: int | None = None
    packets: int | None = None
    connection_status: str | None = None


class EndpointInfo(BaseModel):
    event_type: str | None = None
    hostname: str | None = None
    username: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    parent_process: str | None = None
    executable_path: str | None = None
    command_line: str | None = None
    privilege_level: str | None = None
    keyboard_hook: bool | None = None
    network_connection: bool | None = None
    elevated: bool | None = None


class IdentityInfo(BaseModel):
    user_id: str | None = None
    session_id: str | None = None
    roles: list[str] = Field(default_factory=list)
    is_authenticated: bool = False


class RequestInfo(BaseModel):
    method: str
    endpoint: str
    path_params: dict[str, Any] = Field(default_factory=dict)
    query_params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, Any] = Field(default_factory=dict)
    body: Any = None


class ResponseInfo(BaseModel):
    status_code: int
    latency_ms: float | None = None


class ResourceInfo(BaseModel):
    resource_type: str | None = None
    resource_id: str | None = None
    owner_id: str | None = None
    is_sensitive: bool = False


class ApiSecurityEvent(BaseModel):
    schema_version: str = "1.0"
    event_id: str
    timestamp: datetime
    domain: str = "API"

    network: NetworkInfo
    identity: IdentityInfo
    request: RequestInfo
    response: ResponseInfo
    resource: ResourceInfo = Field(default_factory=ResourceInfo)
    endpoint: EndpointInfo | None = None