"""Regression tests for XGBoost's CICIDS feature-name compatibility."""

from __future__ import annotations

import unittest

import pandas as pd

from ml.api.predictor import prepare_features


class FakeScaler:
    feature_names_in_ = ("Flow Duration", "Fwd Packet Length Max")


class XGBoostFeatureContractTests(unittest.TestCase):
    def test_accepts_normalized_prepared_feature_names(self) -> None:
        prepared = prepare_features(
            {"Flow_Duration": 20.0, "Fwd_Packet_Length_Max": 512.0},
            FakeScaler(),
        )

        self.assertEqual(list(prepared.columns), list(FakeScaler.feature_names_in_))
        self.assertEqual(prepared.iloc[0].tolist(), [20.0, 512.0])

    def test_rejects_ambiguous_normalized_feature_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "Ambiguous feature names"):
            prepare_features(
                pd.Series({"Flow Duration": 20.0, "Flow_Duration": 21.0}).to_dict(),
                FakeScaler(),
            )


if __name__ == "__main__":
    unittest.main()
