from backend.schemas.detector_result import DetectorResult
from backend.schemas.ml_result import MLResult
from backend.schemas.risk_assessment import RiskAssessment


class RiskEngine:

    # -------------------------------------------------
    # Severity base scores
    # -------------------------------------------------

    SEVERITY_SCORES = {
        "LOW": 20.0,
        "MEDIUM": 45.0,
        "HIGH": 70.0,
        "CRITICAL": 90.0,
    }

    # -------------------------------------------------
    # Risk thresholds
    # -------------------------------------------------

    CRITICAL_THRESHOLD = 90
    HIGH_THRESHOLD = 70
    MEDIUM_THRESHOLD = 40

    def assess(
        self,
        event_id: str,
        detector_results: list[DetectorResult] | None = None,
        ml_result: MLResult | None = None,
    ) -> RiskAssessment:
        """
        Combine API detector and ML signals into one
        dynamic risk assessment.

        Risk considers:
        - detector severity
        - detector confidence
        - multiple detected threats
        - ML attack confidence
        - anomaly detection
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
        # Dynamic detector risk
        # -------------------------------------------------

        detector_scores = []

        for result in detected_results:

            severity = str(
                result.severity
            ).upper()

            severity_score = self.SEVERITY_SCORES.get(
                severity,
                20.0
            )

            confidence_score = (
                result.confidence * 100
            )

            # -------------------------------------------------
            # Combine severity + confidence
            #
            # 60% severity
            # 40% confidence
            # -------------------------------------------------

            score = (
                severity_score * 0.60
                + confidence_score * 0.40
            )

            detector_scores.append(score)

        detector_score = 0.0

        if detector_scores:
            detector_score = max(detector_scores)

        # -------------------------------------------------
        # Multiple detector bonus
        # -------------------------------------------------

        # If several different detectors detect the same
        # event, increase the risk slightly because the
        # evidence is stronger.

        if len(detected_results) >= 2:
            detector_score += min(
                (len(detected_results) - 1) * 5,
                15
            )

        detector_score = min(
            detector_score,
            100.0
        )

        # -------------------------------------------------
        # ML signals
        # -------------------------------------------------

        ml_score = 0.0
        ml_anomaly = False

        if ml_result is not None:

            prediction = (
                ml_result.detection.prediction
            )

            confidence = (
                ml_result.detection.confidence
            )

            ml_anomaly = (
                ml_result.anomaly.is_anomaly
            )

            # -------------------------------------------------
            # XGBoost attack prediction
            # -------------------------------------------------

            if prediction.upper() != "BENIGN":

                ml_score = confidence * 100

                attack_types.append(
                    prediction
                )

                explanation = (
                    ml_result.detection.attack_explanation
                )

                if isinstance(
                    explanation,
                    dict
                ):

                    summary = explanation.get(
                        "summary"
                    )

                    if summary:
                        reasons.append(
                            summary
                        )

            # -------------------------------------------------
            # Isolation Forest anomaly
            # -------------------------------------------------

            if ml_anomaly:

                reasons.append(
                    "Isolation Forest detected anomalous network behavior."
                )

                # Anomaly is supporting evidence,
                # not a direct attack probability.

                ml_score = max(
                    ml_score,
                    50.0
                )

        # -------------------------------------------------
        # Combine detector + ML scores
        # -------------------------------------------------

        if detector_score > 0 and ml_score > 0:

            # When both systems agree, increase confidence
            # in the overall assessment.

            risk_score = (
                detector_score * 0.70
                + ml_score * 0.30
            )

        else:

            risk_score = max(
                detector_score,
                ml_score
            )

        # -------------------------------------------------
        # Final anomaly bonus
        # -------------------------------------------------

        if ml_anomaly:

            risk_score += 10.0

        # -------------------------------------------------
        # Clamp score
        # -------------------------------------------------

        risk_score = min(
            max(risk_score, 0.0),
            100.0
        )

        # -------------------------------------------------
        # Risk level
        # -------------------------------------------------

        if risk_score >= self.CRITICAL_THRESHOLD:

            risk_level = "CRITICAL"

        elif risk_score >= self.HIGH_THRESHOLD:

            risk_level = "HIGH"

        elif risk_score >= self.MEDIUM_THRESHOLD:

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
                and
                ml_result.detection.prediction.upper()
                != "BENIGN"
            )
            or ml_anomaly
        )

        # -------------------------------------------------
        # Return assessment
        # -------------------------------------------------

        return RiskAssessment(
            event_id=event_id,

            risk_score=round(
                risk_score,
                2
            ),

            risk_level=risk_level,

            threat_detected=threat_detected,

            attack_types=list(
                dict.fromkeys(
                    attack_types
                )
            ),

            reasons=list(
                dict.fromkeys(
                    reasons
                )
            ),

            detector_count=len(
                detector_results
            ),

            ml_anomaly=ml_anomaly,
        )