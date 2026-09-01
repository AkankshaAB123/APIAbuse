from schemas.detector_result import DetectorResult
from schemas.risk_assessment import RiskAssessment


class RiskEngine:

    def assess(
        self,
        event_id: str,
        detector_results: list[DetectorResult] | None = None,
        ml_attack_probability: float = 0.0,
        ml_is_anomaly: bool = False,
        ml_anomaly_score: float = 0.0,
    ) -> RiskAssessment:
        """
        Combine available detection signals into a preliminary
        risk assessment.

        The final scoring strategy will be refined after the
        detector, ML, and RAG interfaces are finalized.
        """

        detector_results = detector_results or []

        attack_types = []
        reasons = []

        # -------------------------------------------------
        # API detector signals
        # -------------------------------------------------

        for result in detector_results:
            if result.detected:
                if result.attack_type:
                    attack_types.append(result.attack_type)

                for evidence in result.evidence:
                    reasons.append(evidence.message)

        # -------------------------------------------------
        # Preliminary risk signals
        # -------------------------------------------------

        detector_score = 0.0

        if detector_results:
            detected_results = [
                result for result in detector_results
                if result.detected
            ]

            if detected_results:
                detector_score = max(
                    result.confidence * 100
                    for result in detected_results
                )

        ml_score = ml_attack_probability * 100

        if ml_is_anomaly:
            ml_score = max(ml_score, 50.0)

        # -------------------------------------------------
        # Preliminary combined score
        # -------------------------------------------------

        risk_score = max(detector_score, ml_score)

        risk_score = min(risk_score, 100.0)

        # -------------------------------------------------
        # Risk level
        # -------------------------------------------------

        if risk_score >= 90:
            risk_level = "CRITICAL"
        elif risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        threat_detected = (
            bool(attack_types)
            or ml_attack_probability >= 0.5
            or ml_is_anomaly
        )

        return RiskAssessment(
            event_id=event_id,
            risk_score=risk_score,
            risk_level=risk_level,
            threat_detected=threat_detected,
            attack_types=list(dict.fromkeys(attack_types)),
            reasons=list(dict.fromkeys(reasons)),
        )