from pydantic import BaseModel, Field

from backend.schemas.detector_result import DetectorResult
from backend.schemas.ml_result import MLResult
from backend.schemas.risk_assessment import RiskAssessment


class ProcessingResult(BaseModel):
    event_id: str
    source_ip: str | None = None
    status: str
    message: str
    detector_results: list[DetectorResult] = Field(default_factory=list)
    ml_result: MLResult | None = None
    risk_assessment: RiskAssessment | None = None
    mitigation_action: str = "ALLOW"