from typing import Any

from pydantic import BaseModel, Field


class MLDetectionResult(BaseModel):
    prediction: str
    confidence: float = Field(ge=0.0, le=1.0)
    attack_explanation: dict[str, Any] = Field(default_factory=dict)
    reasons: list[dict[str, Any]] = Field(default_factory=list)
    model: str


class AnomalyDetectionResult(BaseModel):
    is_anomaly: bool
    anomaly_score: float


class MLResult(BaseModel):
    detection: MLDetectionResult
    anomaly: AnomalyDetectionResult