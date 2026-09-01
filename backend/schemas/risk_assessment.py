from pydantic import BaseModel, Field


class RiskAssessment(BaseModel):
    event_id: str
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: str
    threat_detected: bool
    attack_types: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)