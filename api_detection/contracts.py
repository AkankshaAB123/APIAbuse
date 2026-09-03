"""Stable input and output contracts for the API detection module."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    

class DetectorDomain(str, Enum):
    API = "API"
    NETWORK = "NETWORK"
    ENDPOINT = "ENDPOINT"




class AttackType(str, Enum):
    BOLA_IDOR = "BOLA_IDOR"
    BROKEN_FUNCTION_LEVEL_AUTHORIZATION = "BROKEN_FUNCTION_LEVEL_AUTHORIZATION"
    CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    SQL_INJECTION = "SQL_INJECTION"
    SSRF = "SSRF"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    BUSINESS_FLOW_ABUSE = "BUSINESS_FLOW_ABUSE"
    ENDPOINT_ENUMERATION = "ENDPOINT_ENUMERATION"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    DDOS = "DDOS"
    DOS_FLOODING = "DOS_FLOODING"
    PORT_SCANNING = "PORT_SCANNING"
    NETWORK_BRUTE_FORCE = "NETWORK_BRUTE_FORCE"
    KEYLOGGING = "KEYLOGGING"
    SUSPICIOUS_PROCESS_EXECUTION = "SUSPICIOUS_PROCESS_EXECUTION"
    REVERSE_SHELL = "REVERSE_SHELL"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
   


@dataclass(frozen=True)
class NetworkInfo:
    source_ip: str
    user_agent: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    bytes: int | None = None
    packets: int | None = None
    connection_status: str | None = None

@dataclass(frozen=True)
class EndpointInfo:
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


@dataclass(frozen=True)
class IdentityInfo:
    user_id: str | None = None
    session_id: str | None = None
    roles: tuple[str, ...] = ()
    is_authenticated: bool = False


@dataclass(frozen=True)
class RequestInfo:
    method: str
    endpoint: str
    path_params: dict[str, Any] = field(default_factory=dict)
    query_params: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None


@dataclass(frozen=True)
class ResponseInfo:
    status_code: int
    latency_ms: float | None = None


@dataclass(frozen=True)
class ResourceInfo:
    resource_type: str | None = None
    resource_id: str | None = None
    owner_id: str | None = None
    is_sensitive: bool = False


@dataclass(frozen=True)
class ApiSecurityEvent:
    """A single API request plus its response and resource context."""

    event_id: str
    timestamp: str
    network: NetworkInfo
    identity: IdentityInfo
    request: RequestInfo
    response: ResponseInfo
    resource: ResourceInfo = field(default_factory=ResourceInfo)
    endpoint: EndpointInfo | None = None
    schema_version: str = "1.0"


@dataclass(frozen=True)
class Evidence:
    code: str
    message: str


@dataclass(frozen=True)
class DetectorResult:
    """The required result shape returned by every Member 2 detector."""

    event_id: str
    detector_id: str
    detected: bool
    attack_type: AttackType | None
    confidence: float
    severity: Severity
    evidence: tuple[Evidence, ...] = ()
    source: str = "api_detector"
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "1.0"
    domain: DetectorDomain = DetectorDomain.API

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if self.detected != (self.attack_type is not None):
            raise ValueError("detected and attack_type must agree")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready representation for the backend owner."""
        result = asdict(self)
        result["attack_type"] = self.attack_type.value if self.attack_type else None
        result["severity"] = self.severity.value
        return result
