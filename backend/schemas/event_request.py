from pydantic import BaseModel
from typing import Any, Optional
from backend.schemas.api_security_event import ApiSecurityEvent

class EventProcessingRequest(BaseModel):
    event: ApiSecurityEvent
    ml_features: Optional[dict[str, Any]] = None
