"""Tests for Member 1's session and transaction anomaly scorer."""

from __future__ import annotations

import unittest

from ml.api import BehaviourAnomalyDetector, FeatureValidationError


NORMAL_BASELINE = [
    {"amount": 20, "requests_per_minute": 2, "failed_auth": 0},
    {"amount": 25, "requests_per_minute": 3, "failed_auth": 0},
    {"amount": 18, "requests_per_minute": 2, "failed_auth": 0},
    {"amount": 22, "requests_per_minute": 2, "failed_auth": 0},
    {"amount": 21, "requests_per_minute": 3, "failed_auth": 0},
]


class BehaviourAnomalyTests(unittest.TestCase):
    def test_scores_unusual_transaction_against_normal_baseline(self) -> None:
        detector = BehaviourAnomalyDetector(contamination=0.2).fit(NORMAL_BASELINE)

        result = detector.analyze(
            "evt-transaction-1",
            {"amount": 5000, "requests_per_minute": 80, "failed_auth": 8},
        )

        self.assertTrue(result.is_anomalous)
        self.assertGreater(result.anomaly_score, 0.5)
        self.assertEqual(result.model, "isolation_forest_behaviour")

    def test_rejects_feature_schema_change(self) -> None:
        detector = BehaviourAnomalyDetector().fit(NORMAL_BASELINE)

        with self.assertRaises(FeatureValidationError):
            detector.analyze("evt-bad", {"amount": 25, "requests_per_minute": 2})

    def test_rejects_non_finite_behaviour_telemetry(self) -> None:
        detector = BehaviourAnomalyDetector().fit(NORMAL_BASELINE)

        with self.assertRaises(FeatureValidationError):
            detector.analyze(
                "evt-infinite",
                {"amount": float("inf"), "requests_per_minute": 2, "failed_auth": 0},
            )


if __name__ == "__main__":
    unittest.main()
