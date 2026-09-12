"""Baseline-trained anomaly scoring for session and transaction behaviour.

Unlike the CICIDS model, this scorer deliberately accepts only metrics collected
from the team's demo banking/session flow.  It must be fitted with normal demo
traffic before it is used, so network-flow training data is never misrepresented
as transaction training data.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import exp
from typing import Any, Iterable

from .security_anomaly import FeatureValidationError, MLResult


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + exp(-value))
    exponent = exp(value)
    return exponent / (1.0 + exponent)


@dataclass
class BehaviourAnomalyDetector:
    """Isolation Forest profile trained from known-normal scenario telemetry."""

    contamination: float = 0.05
    random_state: int = 42
    _feature_names: tuple[str, ...] | None = None
    _scaler: Any = None
    _model: Any = None

    def fit(self, normal_samples: Iterable[dict[str, Any]]) -> "BehaviourAnomalyDetector":
        """Fit a profile from normal session/transaction samples only."""
        try:
            import pandas as pd
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ImportError as error:  # pragma: no cover - deployment configuration
            raise RuntimeError("pandas and scikit-learn are required for behaviour scoring") from error

        samples = list(normal_samples)
        if len(samples) < 2:
            raise FeatureValidationError("at least two normal baseline samples are required")
        if not all(isinstance(sample, dict) and sample for sample in samples):
            raise FeatureValidationError("normal baseline samples must be non-empty dictionaries")

        feature_names = tuple(samples[0])
        if not feature_names:
            raise FeatureValidationError("baseline samples must contain features")
        if any(set(sample) != set(feature_names) for sample in samples):
            raise FeatureValidationError("all baseline samples must use the same features")

        try:
            frame = pd.DataFrame(samples, columns=feature_names).astype(float)
        except (TypeError, ValueError) as error:
            raise FeatureValidationError("behaviour features must be numeric") from error
        if not frame.map(lambda value: value == value and abs(value) != float("inf")).all().all():
            raise FeatureValidationError("behaviour features must be finite")

        scaler = StandardScaler().fit(frame)
        scaled = pd.DataFrame(scaler.transform(frame), columns=feature_names, index=frame.index)
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
        ).fit(scaled)
        self._feature_names = feature_names
        self._scaler = scaler
        return self

    def analyze(self, event_id: str, features: dict[str, Any]) -> MLResult:
        """Return the common ML result for one session/transaction event."""
        if not event_id:
            raise ValueError("event_id is required")
        if self._model is None or self._scaler is None or self._feature_names is None:
            raise RuntimeError("fit the behaviour anomaly detector before scoring events")
        if not isinstance(features, dict) or set(features) != set(self._feature_names):
            raise FeatureValidationError(
                "behaviour features must exactly match the trained baseline features"
            )

        try:
            import pandas as pd

            frame = pd.DataFrame([features], columns=self._feature_names).astype(float)
        except (TypeError, ValueError) as error:
            raise FeatureValidationError("behaviour features must be numeric") from error
        if not frame.map(lambda value: value == value and abs(value) != float("inf")).all().all():
            raise FeatureValidationError("behaviour features must be finite")

        scaled = pd.DataFrame(
            self._scaler.transform(frame), columns=self._feature_names, index=frame.index
        )
        decision = float(self._model.decision_function(scaled)[0])
        anomaly_score = _sigmoid(-decision)
        return MLResult(
            event_id=event_id,
            is_anomalous=bool(self._model.predict(scaled)[0] == -1),
            anomaly_score=round(anomaly_score, 6),
            confidence=round(abs(anomaly_score - 0.5) * 2.0, 6),
            model="isolation_forest_behaviour",
        )
