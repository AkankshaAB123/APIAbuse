from typing import Any

from pydantic import BaseModel, Field

from backend.schemas.api_security_event import ApiSecurityEvent

class EventProcessingRequest(BaseModel):
    event: ApiSecurityEvent
    ml_features: dict[str, Any] | None = Field(default=None)