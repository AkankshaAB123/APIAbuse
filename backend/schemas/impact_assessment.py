from typing import Any
from pydantic import BaseModel, Field


class ImpactAssessment(BaseModel):
    impact_identified: bool = False
    categories: list[str] = Field(default_factory=list)
    primary_impact: str | None = None
    severity: str = "LOW"
    reasons: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
