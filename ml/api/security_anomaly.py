"""Normalized ML anomaly analysis for events in the central IDS pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from math import exp
from pathlib import Path
from typing import Any, Protocol


class Scaler(Protocol):
    feature_names_in_: Any

    def transform(self, values: Any) -> Any: ...


class AnomalyModel(Protocol):
    def predict(self, values: Any) -> Any: ...

    def decision_function(self, values: Any) -> Any: ...


@dataclass(frozen=True)
class MLResult:
    """Stable result sent to the backend by the Member 1 ML component."""

    event_id: str
    is_anomalous: bool
    anomaly_score: float
    confidence: float
    model: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FeatureValidationError(ValueError):
    """Raised when an event does not contain the trained flow features."""


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + exp(-value))
    exponent = exp(value)
    return exponent / (1.0 + exponent)


def _prepare_features(features: dict[str, Any], scaler: Scaler) -> Any:
    if not isinstance(features, dict) or not features:
        raise FeatureValidationError("network_features must be a non-empty dictionary")

    try:
        import pandas as pd
    except ImportError as error:  # pragma: no cover - deployment configuration
        raise RuntimeError("pandas is required to run ML anomaly analysis") from error

    expected = list(getattr(scaler, "feature_names_in_", ()))
    if not expected:
        raise FeatureValidationError("the trained scaler has no feature-name metadata")

    missing = [name for name in expected if name not in features]
    if missing:
        raise FeatureValidationError(
            "network_features is missing trained model features: " + ", ".join(missing)
        )

    row = pd.DataFrame([{name: features[name] for name in expected}])
    try:
        row = row.astype(float)
    except (TypeError, ValueError) as error:
        raise FeatureValidationError("network_features must contain numeric values") from error
    if not row.map(lambda value: value == value and abs(value) != float("inf")).all().all():
        raise FeatureValidationError("network_features must contain finite values")

    # ``StandardScaler.transform`` normally returns a NumPy array.  Restore the
    # labelled frame before passing it to the model: the persisted Isolation
    # Forest was trained with feature names, and this prevents a caller from
    # accidentally changing the feature order at prediction time.
    scaled = scaler.transform(row)
    return pd.DataFrame(scaled, columns=expected, index=row.index)


def analyze_event(
    event_id: str,
    network_features: dict[str, Any],
    *,
    model: AnomalyModel | None = None,
    scaler: Scaler | None = None,
) -> MLResult:
    """Score one event with Isolation Forest using its original training schema.

    API request fields are intentionally not invented as CICIDS flow features. Callers must
    provide observed network-flow telemetry with the same feature names used in training.
    """
    if not event_id:
        raise ValueError("event_id is required")

    if model is None or scaler is None:
        model, scaler = load_default_artifacts()

    prepared_features = _prepare_features(network_features, scaler)
    prediction = int(model.predict(prepared_features)[0])
    decision = float(model.decision_function(prepared_features)[0])

    # Isolation Forest returns lower (negative) decisions for anomalous samples.
    anomaly_score = _sigmoid(-decision)
    confidence = abs(anomaly_score - 0.5) * 2.0
    return MLResult(
        event_id=event_id,
        is_anomalous=prediction == -1,
        anomaly_score=round(anomaly_score, 6),
        confidence=round(confidence, 6),
        model="isolation_forest",
    )


def load_default_artifacts() -> tuple[AnomalyModel, Scaler]:
    """Load the persisted Member 1 Isolation Forest and its matching scaler."""
    try:
        import joblib
    except ImportError as error:  # pragma: no cover - deployment configuration
        raise RuntimeError("joblib is required to load ML anomaly artifacts") from error

    models_directory = Path(__file__).resolve().parent.parent / "models"
    model_path = models_directory / "isolation_forest.pkl"
    scaler_path = models_directory / "scaler.pkl"
    if not model_path.exists() or not scaler_path.exists():
        raise FileNotFoundError("Isolation Forest model and scaler must be trained first")
    return joblib.load(model_path), joblib.load(scaler_path)
