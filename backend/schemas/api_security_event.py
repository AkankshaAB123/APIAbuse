from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class NetworkInfo(BaseModel):
    source_ip: str
    user_agent: str


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
    latency_ms: float


class ResourceInfo(BaseModel):
    resource_type: str | None = None
    resource_id: str | None = None
    owner_id: str | None = None
    is_sensitive: bool = False


class ApiSecurityEvent(BaseModel):
    schema_version: str = "1.0"
    event_id: str
    timestamp: datetime

    network: NetworkInfo
    identity: IdentityInfo
    request: RequestInfo
    response: ResponseInfo
    resource: ResourceInfo