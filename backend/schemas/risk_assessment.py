from pydantic import BaseModel

class RiskAssessment(BaseModel):
    risk_score: float
    risk_level: str
    reasons: list[str] = []
    threat_detected: bool = False
    attack_types: list[str] = []
