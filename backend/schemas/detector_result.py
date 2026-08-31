from typing import Any

from pydantic import BaseModel, Field


class DetectionEvidence(BaseModel):
    code: str
    message: str


class DetectorMetadata(BaseModel):
    rule_version: str = "1.0"
    window_seconds: int = 0


class DetectorResult(BaseModel):
    schema_version: str = "1.0"
    event_id: str
    detector_id: str
    detected: bool
    attack_type: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str
    evidence: list[DetectionEvidence] = Field(default_factory=list)
    source: str = "api_detector"
    metadata: DetectorMetadata