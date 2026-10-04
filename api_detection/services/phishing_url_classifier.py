"""Reusable, thread-safe inference service for the v3 Phishing URL Classifier.

SECURITY CONSTRAINTS:
- NEVER makes network requests (HTTP, DNS, WHOIS), DOM/HTML inspection, or external API calls.
- Purely extracts features deterministically from the URL string.
- Safely normalizes schemeless URLs identical to the v3 training pipeline.
"""
from __future__ import annotations

import pickle
import threading
from pathlib import Path
from typing import Any

from ..features.url_features import FEATURE_NAMES, extract_url_feature_vector

DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent.parent / "models" / "phishing_url_classifier_v3.pkl"
)
MODEL_VERSION = "v3"
DEFAULT_THRESHOLD = 0.60
GATED_THRESHOLD = 0.95


class PhishingURLClassifierService:
    """Thread-safe prediction service for the v3 Random Forest Phishing URL Classifier."""

    _instance: PhishingURLClassifierService | None = None
    _lock = threading.Lock()

    def __init__(self, model_path: Path | str | None = None) -> None:
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self._model: Any = None
        self._load_lock = threading.Lock()

    def _ensure_model_loaded(self) -> Any:
        if self._model is None:
            with self._load_lock:
                if self._model is None:
                    if not self.model_path.exists():
                        raise FileNotFoundError(
                            f"Phishing URL model artifact not found at {self.model_path}"
                        )
                    with open(self.model_path, "rb") as f:
                        self._model = pickle.load(f)
        return self._model

    def predict(self, url: str) -> dict[str, Any]:
        """Predict phishing probability for a given URL string.

        Args:
            url: The raw URL or domain string to inspect.

        Returns:
            Dictionary containing model_version, probability, threshold,
            gated_threshold, prediction, is_high_confidence, features metadata.
        """
        raw_url = str(url or "").strip()
        if not raw_url:
            return {
                "model_version": MODEL_VERSION,
                "probability": 0.0,
                "threshold": DEFAULT_THRESHOLD,
                "gated_threshold": GATED_THRESHOLD,
                "prediction": "BENIGN",
                "is_high_confidence": False,
                "raw_url": raw_url,
                "normalized_url": "",
                "features": {fn: 0.0 for fn in FEATURE_NAMES},
            }

        # Safely handle schemeless URLs exactly as in v3 training
        normalized_url = raw_url if "://" in raw_url else f"http://{raw_url}"

        # Extract deterministic 29-feature numerical vector
        feature_vector = extract_url_feature_vector(normalized_url)

        model = self._ensure_model_loaded()
        prob = float(model.predict_proba([feature_vector])[0, 1])

        return {
            "model_version": MODEL_VERSION,
            "probability": prob,
            "threshold": DEFAULT_THRESHOLD,
            "gated_threshold": GATED_THRESHOLD,
            "prediction": "PHISHING" if prob >= DEFAULT_THRESHOLD else "BENIGN",
            "is_high_confidence": prob >= GATED_THRESHOLD,
            "raw_url": raw_url,
            "normalized_url": normalized_url,
            "features": {fn: float(val) for fn, val in zip(FEATURE_NAMES, feature_vector)},
        }


def get_phishing_url_classifier(
    model_path: Path | str | None = None,
) -> PhishingURLClassifierService:
    """Return a thread-safe singleton instance of PhishingURLClassifierService."""
    if PhishingURLClassifierService._instance is None:
        with PhishingURLClassifierService._lock:
            if PhishingURLClassifierService._instance is None:
                PhishingURLClassifierService._instance = PhishingURLClassifierService(model_path)
    return PhishingURLClassifierService._instance
