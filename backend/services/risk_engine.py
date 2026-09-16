from backend.schemas.risk_assessment import RiskAssessment
from backend.schemas.api_security_event import ApiSecurityEvent
from backend.schemas.detector_result import DetectorResult
from backend.schemas.ml_result import MLResult

class RiskEngine:
    def assess(
        self,
        event_id: str,
        detector_results: list[DetectorResult],
        ml_result: MLResult | None = None
    ) -> RiskAssessment:
        
        score = 0
        reasons = []

        if detector_results:
            score += 50
            reasons.append("API Detection rule triggered")
            
        if ml_result and ml_result.anomaly and ml_result.anomaly.is_anomaly:
            score += 40
            reasons.append(f"Network anomaly detected (score: {ml_result.anomaly.anomaly_score:.2f})")
            
        if ml_result and ml_result.detection and ml_result.detection.prediction != "BENIGN":
            score += 30
            reasons.append(f"ML classified as {ml_result.detection.prediction}")

        score = min(100, score)

        if score >= 90:
            level = "CRITICAL"
        elif score >= 70:
            level = "HIGH"
        elif score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"
            
        if score == 0:
            reasons.append("No suspicious activity detected")

        return RiskAssessment(
            risk_score=float(score),
            risk_level=level,
            reasons=reasons,
            threat_detected=bool(detector_results) or (ml_result and ml_result.detection.prediction != "BENIGN"),
            attack_types=list({d.attack_type.value if hasattr(d.attack_type, 'value') else d.attack_type for d in detector_results if d.attack_type})
        )
