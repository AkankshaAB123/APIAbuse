import json
import socket
from pathlib import Path
import joblib
import numpy as np
import pytest

from api_detection.features.url_features import (
    FEATURE_NAMES,
    extract_url_feature_vector,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = REPO_ROOT / "api_detection" / "models" / "phishing_url_classifier.pkl"
META_PATH = REPO_ROOT / "api_detection" / "models" / "phishing_url_model_meta.json"


def test_model_artifact_exists_and_loads():
    assert MODEL_PATH.exists(), f"Model file missing: {MODEL_PATH}"
    model = joblib.load(MODEL_PATH)
    assert hasattr(model, "predict_proba"), "Model must implement predict_proba"
    assert hasattr(model, "predict"), "Model must implement predict"


def test_metadata_file_validity():
    assert META_PATH.exists(), f"Metadata file missing: {META_PATH}"
    meta = json.loads(META_PATH.read_text(encoding="utf-8"))

    assert meta["status"] == "EXPERIMENTAL — NOT APPROVED FOR PRODUCTION INTEGRATION"
    assert meta["dataset"]["filename"] == "malicious_phish.csv"
    assert "sha256" in meta["dataset"]
    assert meta["dataset"]["label_mapping"] == {"benign": 0, "phishing": 1}

    # Verify split metadata
    assert "split" in meta
    assert meta["split"]["overlap_audit"]["train_val_domain_overlap"] == 0
    assert meta["split"]["overlap_audit"]["train_test_domain_overlap"] == 0
    assert meta["split"]["overlap_audit"]["val_test_domain_overlap"] == 0
    assert meta["split"]["overlap_audit"]["train_val_url_overlap"] == 0
    assert meta["split"]["overlap_audit"]["train_test_url_overlap"] == 0
    assert meta["split"]["overlap_audit"]["val_test_url_overlap"] == 0

    # Verify feature specification
    assert meta["feature_specification"]["num_features"] == 29
    assert tuple(meta["feature_specification"]["feature_names"]) == FEATURE_NAMES
    assert meta["feature_specification"]["order_verified"] is True
    assert meta["feature_specification"]["network_calls"] is False

    # Verify metrics presence
    assert "validation_metrics_all_candidates" in meta
    assert "untouched_test_metrics_selected" in meta
    assert "legitimate_url_calibration" in meta


def test_feature_names_order_frozen():
    model = joblib.load(MODEL_PATH)
    assert len(FEATURE_NAMES) == 29
    assert FEATURE_NAMES[0] == "url_length"
    assert FEATURE_NAMES[-1] == "query_entropy"
    # Check model features match
    if hasattr(model, "n_features_in_"):
        assert model.n_features_in_ == 29


def test_deterministic_inference():
    model = joblib.load(MODEL_PATH)
    sample_urls = [
        "https://example.com/test",
        "http://paypa1-secure.login.xyz/verify?id=123",
        "https://google.com/search?q=weather",
    ]
    for url in sample_urls:
        vec1 = np.array([extract_url_feature_vector(url)])
        vec2 = np.array([extract_url_feature_vector(url)])
        p1 = model.predict_proba(vec1)[0][1]
        p2 = model.predict_proba(vec2)[0][1]
        assert np.isclose(p1, p2, atol=1e-12), f"Inference non-deterministic for {url}: {p1} vs {p2}"
        assert 0.0 <= p1 <= 1.0, f"Probability out of bounds: {p1}"


def test_zero_network_activity_during_extraction_and_inference(monkeypatch):
    """Confirm strictly zero network calls during feature extraction & model inference."""
    def guarded_socket(*args, **kwargs):
        raise AssertionError("Network socket call attempted during URL inference!")

    monkeypatch.setattr(socket, "socket", guarded_socket)
    monkeypatch.setattr(socket, "create_connection", guarded_socket)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_socket)
    monkeypatch.setattr(socket, "gethostbyname", guarded_socket)

    model = joblib.load(MODEL_PATH)
    test_urls = [
        "https://google.com/",
        "http://paypa1-update.com/login",
        "http://192.168.1.1/admin",
    ]
    for url in test_urls:
        vec = np.array([extract_url_feature_vector(url)])
        proba = model.predict_proba(vec)
        assert proba.shape == (1, 2)
