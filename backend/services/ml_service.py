import json

from backend.schemas.ml_result import (
    AnomalyDetectionResult,
    MLDetectionResult,
    MLResult,
)

from ml.api.predictor import predict
from ml.api.anomaly_detector import detect_anomaly


class MLService:

    def detect(self, features: dict) -> MLResult:
        """
        Run Member 1's XGBoost and Isolation Forest models
        using the provided network-flow features.
        """

        if not isinstance(features, dict):
            raise ValueError("features must be a dictionary")

        if not features:
            raise ValueError("features cannot be empty")

        # XGBoost expects the original CICIDS feature names.
        prediction_json = predict(features)
        prediction_data = json.loads(prediction_json)

        detection_result = MLDetectionResult(
            prediction=prediction_data["prediction"],
            confidence=float(prediction_data["confidence"]),
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

        # Isolation Forest was trained using cleaned feature names.
        anomaly_features = {
            key.replace(" ", "_")
                .replace("/", "_")
                .replace("-", "_"): value
            for key, value in features.items()
        }

        anomaly_data = detect_anomaly(anomaly_features)

        anomaly_result = AnomalyDetectionResult(
            is_anomaly=anomaly_data["is_anomaly"],
            anomaly_score=float(anomaly_data["anomaly_score"]),
        )

        return MLResult(
            detection=detection_result,
            anomaly=anomaly_result,
        )