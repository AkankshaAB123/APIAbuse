from pydantic import BaseModel
from typing import Any

class MLDetectionResult(BaseModel):
    prediction: str
    confidence: float
    attack_explanation: dict[str, Any] = {}
    reasons: list[str] = []
    model: str = "xgboost_multiclass"

class AnomalyDetectionResult(BaseModel):
    is_anomaly: bool
    anomaly_score: float

class MLResult(BaseModel):
    detection: MLDetectionResult
    anomaly: AnomalyDetectionResult
