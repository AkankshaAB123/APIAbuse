from backend.schemas.detector_result import DetectorResult
from backend.schemas.ml_result import MLResult
from backend.schemas.risk_assessment import RiskAssessment


class RiskEngine:

    def assess(
        self,
        event_id: str,
        detector_results: list[DetectorResult] | None = None,
        ml_result: MLResult | None = None,
    ) -> RiskAssessment:
        """
        Combine API detector and ML signals into one risk assessment.
        """

        detector_results = detector_results or []

        attack_types = []
        reasons = []

        # -------------------------------------------------
        # API detector signals
        # -------------------------------------------------

        detected_results = [
            result
            for result in detector_results
            if result.detected
        ]

        for result in detected_results:
            if result.attack_type:
                attack_types.append(result.attack_type)

            for evidence in result.evidence:
                reasons.append(evidence.message)

        # -------------------------------------------------
        # API detector score
        # -------------------------------------------------

        detector_score = 0.0

        if detected_results:
            detector_score = max(
                result.confidence * 100
                for result in detected_results
            )

        # -------------------------------------------------
        # ML signals
        # -------------------------------------------------

        ml_score = 0.0
        ml_anomaly = False

        if ml_result is not None:
            prediction = ml_result.detection.prediction
            confidence = ml_result.detection.confidence

            ml_anomaly = ml_result.anomaly.is_anomaly

            # XGBoost confidence is only treated as an
            # attack signal when the predicted class is
            # actually an attack.
            if prediction.upper() != "BENIGN":
                ml_score = confidence * 100

                attack_types.append(prediction)

                explanation = ml_result.detection.attack_explanation

                if isinstance(explanation, dict):
                    summary = explanation.get("summary")

                    if summary:
                        reasons.append(summary)

            # Isolation Forest is an anomaly signal,
            # not an attack probability.
            if ml_anomaly:
                reasons.append(
                    "Isolation Forest detected anomalous network behavior."
                )

        # -------------------------------------------------
        # Combined risk score
        # -------------------------------------------------

        risk_score = max(detector_score, ml_score)

        # Anomaly detection acts as supporting evidence.
        if ml_anomaly:
            risk_score = max(risk_score, 50.0)

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

        # -------------------------------------------------
        # Threat decision
        # -------------------------------------------------

        threat_detected = (
            bool(detected_results)
            or (
                ml_result is not None
                and ml_result.detection.prediction.upper() != "BENIGN"
            )
            or ml_anomaly
        )

        return RiskAssessment(
            event_id=event_id,
            risk_score=risk_score,
            risk_level=risk_level,
            threat_detected=threat_detected,
            attack_types=list(dict.fromkeys(attack_types)),
            reasons=list(dict.fromkeys(reasons)),
            detector_count=len(detector_results),
            ml_anomaly=ml_anomaly,
        )