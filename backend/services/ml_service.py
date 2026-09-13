import json

from backend.schemas.ml_result import (
    AnomalyDetectionResult,
    MLDetectionResult,
    MLResult,
)

from ml.api.predictor import predict
from ml.api.security_anomaly import analyze_event


class MLService:
    """
    Backend adapter for Member 1's ML services.

    Runs:
    1. XGBoost multiclass classification
    2. Isolation Forest network anomaly detection

    The results are converted into the existing backend MLResult
    contract so RiskEngine, ImpactService, and ProcessingResult
    continue to work without changes.
    """

    def detect(
        self,
        features: dict,
        event_id: str = "unknown",
    ) -> MLResult:
        """
        Run Member 1's XGBoost classifier and Isolation Forest
        network anomaly detector using the supplied CICIDS
        network-flow features.
        """

        if not isinstance(features, dict):
            raise ValueError("features must be a dictionary")

        if not features:
            raise ValueError("features cannot be empty")

        # ----------------------------------------------------
        # 1. XGBoost multiclass classification
        # ----------------------------------------------------

        prediction_json = predict(features)
        prediction_data = json.loads(prediction_json)

        detection_result = MLDetectionResult(
            prediction=prediction_data["prediction"],
            confidence=float(
                prediction_data["confidence"]
            ),
            attack_explanation=prediction_data.get(
                "attack_explanation",
                {},
            ),
            reasons=prediction_data.get(
                "reasons",
                [],
            ),
            model=prediction_data.get(
                "model",
                "xgboost_multiclass",
            ),
        )

        # ----------------------------------------------------
        # 2. Member 1 Isolation Forest anomaly detection
        # ----------------------------------------------------

        anomaly_features = {
            key.replace(" ", "_")
                .replace("/", "_")
                .replace("-", "_"): value
            for key, value in features.items()
        }

        anomaly_result_raw = analyze_event(
            event_id=event_id,
            network_features=anomaly_features,
        )

        anomaly_result = AnomalyDetectionResult(
            is_anomaly=bool(
                anomaly_result_raw.is_anomalous
            ),
            anomaly_score=float(
                anomaly_result_raw.anomaly_score
            ),
        )

        # ----------------------------------------------------
        # 3. Preserve existing backend MLResult contract
        # ----------------------------------------------------

        return MLResult(
            detection=detection_result,
            anomaly=anomaly_result,
        )