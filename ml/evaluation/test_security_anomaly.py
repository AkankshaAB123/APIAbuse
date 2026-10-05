"""Unit tests for the central IDS anomaly-result adapter."""

from __future__ import annotations

import unittest

from ml.api.security_anomaly import FeatureValidationError, analyze_event


class FakeScaler:
    feature_names_in_ = ("flow_duration", "packet_count")

    def transform(self, values):
        return values


class FakeModel:
    def __init__(self, prediction: int, decision: float) -> None:
        self.prediction = prediction
        self.decision = decision

    def predict(self, values):
        return [self.prediction]

    def decision_function(self, values):
        return [self.decision]


class NameCheckingModel(FakeModel):
    def predict(self, values):
        if list(values.columns) != ["flow_duration", "packet_count"]:
            raise AssertionError("model input must preserve the trained feature names")
        return super().predict(values)


class SecurityAnomalyTests(unittest.TestCase):
    def test_returns_normalized_anomaly_result(self) -> None:
        result = analyze_event(
            "evt-flood-1",
            {"flow_duration": 20.0, "packet_count": 9000},
            model=FakeModel(-1, -2.0),
            scaler=FakeScaler(),
        )

        self.assertTrue(result.is_anomalous)
        self.assertGreater(result.anomaly_score, 0.5)
        self.assertGreater(result.confidence, 0.5)
        self.assertEqual(result.to_dict()["event_id"], "evt-flood-1")
        self.assertEqual(result.model, "isolation_forest")

    def test_rejects_incomplete_flow_telemetry(self) -> None:
        with self.assertRaises(FeatureValidationError):
            analyze_event(
                "evt-incomplete",
                {"flow_duration": 20.0},
                model=FakeModel(1, 1.0),
                scaler=FakeScaler(),
            )

    def test_preserves_feature_names_after_scaling(self) -> None:
        result = analyze_event(
            "evt-labelled-input",
            {"flow_duration": 20.0, "packet_count": 10.0},
            model=NameCheckingModel(1, 1.0),
            scaler=FakeScaler(),
        )

        self.assertFalse(result.is_anomalous)

    def test_rejects_non_finite_flow_telemetry(self) -> None:
        with self.assertRaises(FeatureValidationError):
            analyze_event(
                "evt-infinite",
                {"flow_duration": float("inf"), "packet_count": 10.0},
                model=FakeModel(1, 1.0),
                scaler=FakeScaler(),
            )


if __name__ == "__main__":
    unittest.main()
