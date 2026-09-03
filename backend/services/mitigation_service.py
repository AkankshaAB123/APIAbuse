from backend.schemas.risk_assessment import RiskAssessment


class MitigationService:

    def decide_action(self, risk_assessment: RiskAssessment) -> str:
        """Decide the recommended mitigation action based on risk level."""

        if not risk_assessment.threat_detected:
            return "ALLOW"

        if risk_assessment.risk_level == "CRITICAL":
            return "BLOCK"

        if risk_assessment.risk_level == "HIGH":
            return "RATE_LIMIT"

        if risk_assessment.risk_level == "MEDIUM":
            return "MONITOR"

        return "ALLOW"