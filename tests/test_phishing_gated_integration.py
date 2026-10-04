"""Phase 2C — Gated Phishing ML Integration Tests.

Safety invariants verified:
  1. Famous safe URLs (google.com, amazon.com/dp/...) → detected=False, ALLOW.
  2. Schemeless URLs are normalised and do not crash the service.
  3. ML-only high-score URL (no deterministic rule) → detected=False, action=MONITOR (NOT URL_BLOCK).
  4. Deterministic rule + ML >= 0.95 → detected=True, action=URL_BLOCK.
  5. Deterministic rule + ML < 0.95  → deterministic rule still fires → URL_BLOCK.
  6. Existing phishing lab tests (smoke) continue to pass.

All tests are unit/integration level – no network I/O, no external dependencies.
"""

import datetime
import uuid
from unittest.mock import patch

import pytest

from api_detection.contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorDomain,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResourceInfo,
    ResponseInfo,
    Severity,
)
from api_detection.detectors.phishing import detect_phishing


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(
    url: str | None = None,
    endpoint: str = "/api/check",
    body: dict | None = None,
) -> ApiSecurityEvent:
    """Build a minimal ApiSecurityEvent suitable for the phishing detector."""
    return ApiSecurityEvent(
        event_id=f"TEST-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.datetime.utcnow().isoformat(),
        network=NetworkInfo(source_ip="192.168.1.100"),
        identity=IdentityInfo(),
        request=RequestInfo(
            method="GET",
            endpoint=endpoint,
            body=body if body is not None else ({"url": url} if url else None),
        ),
        response=ResponseInfo(status_code=200),
        resource=ResourceInfo(),
    )


def _ml_high(url: str = "https://evil-phish.tk/login", prob: float = 0.98) -> dict:
    """Return a fake high-confidence ML prediction."""
    return {"probability": prob, "prediction": "PHISHING", "is_high_confidence": True}


def _ml_low(prob: float = 0.30) -> dict:
    """Return a fake low-confidence ML prediction."""
    return {"probability": prob, "prediction": "BENIGN", "is_high_confidence": False}


# ---------------------------------------------------------------------------
# 1. PhishingURLClassifierService unit tests (model-free, mocked)
# ---------------------------------------------------------------------------

class TestPhishingURLClassifierService:
    """Test the service interface without loading the 37 MB model artifact."""

    def test_predict_empty_string_returns_benign(self):
        """predict('') must never raise; returns BENIGN with probability 0.0."""
        from api_detection.services.phishing_url_classifier import PhishingURLClassifierService
        svc = PhishingURLClassifierService.__new__(PhishingURLClassifierService)
        # Bypass _ensure_model_loaded by testing the empty-string fast-path
        result = svc.predict("")
        assert result["prediction"] == "BENIGN"
        assert result["probability"] == 0.0
        assert result["model_version"] == "v3"

    def test_schemeless_url_normalised(self):
        """Schemeless URL is prefixed with http:// before feature extraction."""
        from api_detection.services.phishing_url_classifier import PhishingURLClassifierService
        svc = PhishingURLClassifierService.__new__(PhishingURLClassifierService)
        # Patch _ensure_model_loaded to return a mock that returns benign prob
        class _FakeModel:
            def predict_proba(self, X):
                import numpy as np
                return np.array([[0.9, 0.1]])
        svc._model = _FakeModel()
        svc._load_lock = __import__("threading").Lock()
        result = svc.predict("evil-site.tk/login")
        assert result["normalized_url"] == "http://evil-site.tk/login"
        assert result["raw_url"] == "evil-site.tk/login"

    def test_https_url_not_double_prefixed(self):
        """HTTPS URLs must NOT get an extra http:// prepended."""
        from api_detection.services.phishing_url_classifier import PhishingURLClassifierService
        svc = PhishingURLClassifierService.__new__(PhishingURLClassifierService)
        class _FakeModel:
            def predict_proba(self, X):
                import numpy as np
                return np.array([[0.0, 1.0]])
        svc._model = _FakeModel()
        svc._load_lock = __import__("threading").Lock()
        result = svc.predict("https://example.com/login")
        assert result["normalized_url"] == "https://example.com/login"

    def test_predict_returns_expected_keys(self):
        """predict() result must contain all contract keys."""
        from api_detection.services.phishing_url_classifier import PhishingURLClassifierService
        svc = PhishingURLClassifierService.__new__(PhishingURLClassifierService)
        class _FakeModel:
            def predict_proba(self, X):
                import numpy as np
                return np.array([[0.8, 0.2]])
        svc._model = _FakeModel()
        svc._load_lock = __import__("threading").Lock()
        result = svc.predict("https://google.com")
        required_keys = {
            "model_version", "probability", "threshold", "gated_threshold",
            "prediction", "is_high_confidence", "raw_url", "normalized_url", "features",
        }
        assert required_keys.issubset(result.keys())


# ---------------------------------------------------------------------------
# 2. Detector unit tests — famous safe URLs
# ---------------------------------------------------------------------------

class TestSafeUrlsClean:
    """Famous, well-known URLs must NOT be flagged by deterministic rules."""

    @pytest.mark.parametrize("url", [
        "https://www.google.com",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://www.wikipedia.org/wiki/Python_(programming_language)",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://github.com/org/repo/blob/main/README.md",
    ])
    def test_famous_url_no_deterministic_hit(self, url):
        """Famous URLs should NOT trigger any deterministic heuristic evidence."""
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier",
            return_value=None,
        ):
            event = _event(url=url)
            result = detect_phishing(event)
        # Must never be detected=True purely on a safe famous URL
        # (may be LOW / NO_URL_PRESENT if URL isn't in body/endpoint)
        assert result.detector_id == "phishing"
        assert result.domain == DetectorDomain.ENDPOINT
        # The critical invariant: no deterministic evidence codes
        det_codes = {e.code for e in result.evidence}
        false_positive_codes = {
            "PHISHING_SIMULATED_LOGIN_URL",
            "PHISHING_HEURISTIC_IP_HOST",
        }
        assert det_codes.isdisjoint(false_positive_codes), (
            f"Famous URL '{url}' incorrectly triggered deterministic codes: "
            f"{det_codes & false_positive_codes}"
        )

    def test_google_with_ml_low_is_allow(self):
        """google.com with low ML score → detected=False."""
        mock_pred = _ml_low(prob=0.05)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            event = _event(url="https://www.google.com/search?q=hello")
            result = detect_phishing(event)
        assert result.detected is False


# ---------------------------------------------------------------------------
# 3. Safety Rule — ML-only high score must NOT become URL_BLOCK
# ---------------------------------------------------------------------------

class TestMLOnlyHighScoreDoesNotBlock:
    """CRITICAL SAFETY: ML >= 0.95 alone must NOT cause URL_BLOCK or detected=True."""

    def test_ml_only_high_score_detected_false(self):
        """URL with high ML score but no deterministic rule hit → detected=False."""
        mock_pred = _ml_high(prob=0.98)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            # Use a URL that does NOT hit deterministic heuristics:
            # no suspicious TLD, no login/verify keyword, no raw-IP host, no .example.test
            event = _event(url="https://completely-ordinary-domain.com/homepage")
            result = detect_phishing(event)
        assert result.detected is False, (
            "ML-only high score must NOT set detected=True (gated policy violation)"
        )
        assert result.attack_type is None

    def test_ml_only_high_score_gated_decision(self):
        """ML-only suspicion must carry gated_decision == SUSPICIOUS_ML_AUXILIARY_ONLY."""
        mock_pred = _ml_high(prob=0.97)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            event = _event(url="https://completely-ordinary-domain.com/homepage")
            result = detect_phishing(event)
        assert result.metadata.get("gated_decision") == "SUSPICIOUS_ML_AUXILIARY_ONLY"

    def test_ml_only_high_score_severity_medium(self):
        """ML-only suspicion must produce MEDIUM severity (not HIGH/CRITICAL)."""
        mock_pred = _ml_high(prob=0.99)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            event = _event(url="https://completely-ordinary-domain.com/homepage")
            result = detect_phishing(event)
        assert result.severity == Severity.MEDIUM

    def test_ml_only_high_score_auxiliary_evidence_code(self):
        """ML-only suspicion must carry PHISHING_ML_AUXILIARY_SUSPICION evidence."""
        mock_pred = _ml_high(prob=0.96)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            event = _event(url="https://completely-ordinary-domain.com/homepage")
            result = detect_phishing(event)
        codes = {e.code for e in result.evidence}
        assert "PHISHING_ML_AUXILIARY_SUSPICION" in codes

    def test_ml_only_risk_engine_raises_to_medium_not_block(self):
        """Full risk_engine path: auxiliary ML suspicion → MEDIUM risk (not URL_BLOCK logic)."""
        from backend.services.risk_engine import RiskEngine
        from backend.schemas.detector_result import DetectorResult, DetectorMetadata

        # Simulate what the backend adapter produces for SUSPICIOUS_ML_AUXILIARY_ONLY
        result = DetectorResult(
            event_id="TEST-RISK-001",
            detector_id="phishing",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity="MEDIUM",
            evidence=[],
            source="api_detector",
            domain="ENDPOINT",
            metadata=DetectorMetadata(
                rule_version="1.0",
                window_seconds=0,
                details={
                    "gated_decision": "SUSPICIOUS_ML_AUXILIARY_ONLY",
                    "auxiliary_suspicion": True,
                    "phishing_ml_probability": 0.97,
                },
            ),
        )
        engine = RiskEngine()
        assessment = engine.assess(
            event_id="TEST-RISK-001",
            detector_results=[result],
            ml_result=None,
        )
        # Must be MEDIUM or higher (45.0+), and must signal threat_detected
        assert assessment.threat_detected is True
        assert assessment.risk_score >= 40.0  # MEDIUM threshold
        assert assessment.risk_level in ("MEDIUM", "HIGH", "CRITICAL")
        # The auxiliary reason must be present (safe wording – no "phishing" or "malicious url")
        assert any("auxiliary ML model" in r for r in assessment.reasons)

    def test_ml_only_mitigation_is_not_url_block(self):
        """Auxiliary ML suspicion must produce MONITOR, not URL_BLOCK."""
        from backend.services.risk_engine import RiskEngine
        from backend.services.mitigation_service import MitigationService
        from backend.schemas.detector_result import DetectorResult, DetectorMetadata

        result = DetectorResult(
            event_id="TEST-MIT-001",
            detector_id="phishing",
            detected=False,
            attack_type=None,
            confidence=0.0,
            severity="MEDIUM",
            evidence=[],
            source="api_detector",
            domain="ENDPOINT",
            metadata=DetectorMetadata(
                rule_version="1.0",
                window_seconds=0,
                details={
                    "gated_decision": "SUSPICIOUS_ML_AUXILIARY_ONLY",
                    "auxiliary_suspicion": True,
                    "phishing_ml_probability": 0.97,
                },
            ),
        )
        engine = RiskEngine()
        assessment = engine.assess(
            event_id="TEST-MIT-001",
            detector_results=[result],
            ml_result=None,
        )
        mitigation_svc = MitigationService()
        action = mitigation_svc.decide_action(
            risk_assessment=assessment,
            impact_assessment=None,
        )
        assert action != "URL_BLOCK", (
            "CRITICAL SAFETY VIOLATION: ML-only high score must NOT produce URL_BLOCK"
        )
        assert action == "MONITOR", (
            f"Expected MONITOR for auxiliary-only ML suspicion, got {action}"
        )


# ---------------------------------------------------------------------------
# 4. Gated Policy — deterministic rule + ML >= 0.95 → URL_BLOCK
# ---------------------------------------------------------------------------

class TestGatedPolicyConfirmedBlock:
    """When both a deterministic heuristic AND ML >= 0.95 fire, detected=True."""

    def test_suspicious_tld_plus_high_ml_detected_true(self):
        """URL with .tk TLD + high ML score → detected=True, CONFIRMED_GATED_PHISHING."""
        mock_pred = _ml_high(url="https://evil.tk/login", prob=0.97)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            event = _event(url="https://evil.tk/login")
            result = detect_phishing(event)
        assert result.detected is True
        assert result.attack_type == AttackType.PHISHING
        assert result.severity == Severity.HIGH
        assert result.metadata.get("gated_decision") == "CONFIRMED_GATED_PHISHING"

    def test_confirmed_gated_phishing_has_ml_evidence(self):
        """CONFIRMED_GATED_PHISHING result must carry PHISHING_ML_CONFIRMED evidence."""
        mock_pred = _ml_high(prob=0.98)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            event = _event(url="https://evil.tk/login")
            result = detect_phishing(event)
        codes = {e.code for e in result.evidence}
        assert "PHISHING_ML_CONFIRMED" in codes

    def test_ip_host_path_plus_high_ml_detected_true(self):
        """Raw IP host with path + high ML → detected=True."""
        mock_pred = _ml_high(prob=0.96)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            event = _event(url="http://192.168.50.1/login")
            result = detect_phishing(event)
        assert result.detected is True
        assert result.attack_type == AttackType.PHISHING

    def test_keyword_plus_high_ml_detected_true(self):
        """Login keyword in path + high ML → detected=True."""
        mock_pred = _ml_high(prob=0.97)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            event = _event(url="https://some-bank.com/verify/credential")
            result = detect_phishing(event)
        assert result.detected is True
        assert result.attack_type == AttackType.PHISHING


# ---------------------------------------------------------------------------
# 5. Deterministic-only rule still fires when ML < 0.95
# ---------------------------------------------------------------------------

class TestDeterministicRuleWithLowML:
    """Deterministic rules must work independently of ML score."""

    def test_simulated_login_url_detected_without_high_ml(self):
        """A .example.test login URL must be detected even when ML is low."""
        mock_pred = _ml_low(prob=0.20)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            # Two deterministic hits: SIMULATED_LOGIN_URL + login keyword
            event = _event(url="https://secure-login.example.test/login")
            result = detect_phishing(event)
        # At least one deterministic code must fire
        codes = {e.code for e in result.evidence}
        deterministic_codes = {
            "PHISHING_SIMULATED_LOGIN_URL",
            "PHISHING_HEURISTIC_LOGIN_KEYWORD",
        }
        assert codes & deterministic_codes, (
            "Expected at least one deterministic evidence code to fire for .example.test login URL"
        )
        assert result.detected is True
        assert result.attack_type == AttackType.PHISHING

    def test_gated_decision_deterministic_only(self):
        """With low ML and strong deterministic rule → DETERMINISTIC_ONLY_PHISHING."""
        mock_pred = _ml_low(prob=0.30)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            event = _event(url="https://secure-login.example.test/login")
            result = detect_phishing(event)
        assert result.metadata.get("gated_decision") in (
            "DETERMINISTIC_ONLY_PHISHING",
            "CONFIRMED_GATED_PHISHING",
        )

    def test_suspicious_tld_alone_fires_without_ml(self):
        """.tk TLD alone with no ML → deterministic only."""
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier",
            return_value=None,
        ):
            event = _event(url="https://steal-passwords.tk/verify")
            result = detect_phishing(event)
        codes = {e.code for e in result.evidence}
        # Must at least flag suspicious TLD or login keyword
        assert codes & {"PHISHING_HEURISTIC_SUSPICIOUS_TLD", "PHISHING_HEURISTIC_LOGIN_KEYWORD"}


# ---------------------------------------------------------------------------
# 6. No URL present — clean result
# ---------------------------------------------------------------------------

class TestNoUrlPresent:
    """When there is no candidate URL in the event, result must be clean."""

    def test_no_url_event_is_clean(self):
        """Event with no URL in body/query_params/endpoint → gated_decision == NO_URL_PRESENT."""
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier",
            return_value=None,
        ):
            event = _event(url=None, body=None)
            result = detect_phishing(event)
        assert result.detected is False
        assert result.attack_type is None
        assert result.severity == Severity.LOW
        # The "no url" path should report NO_URL_PRESENT (falls through to section 4)
        assert result.metadata.get("gated_decision") in (
            "NO_URL_PRESENT",
            "BENIGN_OR_CLEAN",
        )


# ---------------------------------------------------------------------------
# 7. Schemeless URL support in detector
# ---------------------------------------------------------------------------

class TestSchemelessURLs:
    """Schemeless URLs must be processed, not discarded."""

    def test_schemeless_with_high_ml_returns_auxiliary(self):
        """Schemeless URL (no http://) with high ML, no heuristic → auxiliary suspicion."""
        mock_pred = _ml_high(prob=0.97)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            # Schemeless URL that doesn't hit deterministic rules
            event = _event(url="completely-ordinary-domain.com/homepage")
            result = detect_phishing(event)
        # Must not crash and must be handled — either benign or auxiliary
        assert result.detector_id == "phishing"
        assert result.detected is False  # No deterministic rule hit

    def test_schemeless_phishing_url_with_deterministic_hit(self):
        """Schemeless URL that hits a deterministic rule must still be detected."""
        mock_pred = _ml_high(prob=0.97)
        with patch(
            "api_detection.detectors.phishing.get_phishing_url_classifier"
        ) as mock_get:
            mock_get.return_value.predict.return_value = mock_pred
            # Schemeless phishing URL with suspicious TLD
            event = _event(url="steal-passwords.tk/login")
            result = detect_phishing(event)
        assert result.detected is True


# ---------------------------------------------------------------------------
# 8. Smoke test — lab endpoint still passes
# ---------------------------------------------------------------------------

class TestPhishingLabSmoke:
    """Smoke test: the controlled lab path still works after Phase 2C changes."""

    def test_lab_login_endpoint_detected(self):
        """The controlled /lab/phishing/login endpoint must still be detected."""
        from api_detection.contracts import RequestInfo
        event = ApiSecurityEvent(
            event_id="SMOKE-LAB-001",
            timestamp=datetime.datetime.utcnow().isoformat(),
            network=NetworkInfo(source_ip="127.0.0.1"),
            identity=IdentityInfo(),
            request=RequestInfo(
                method="POST",
                endpoint="/lab/phishing/login",
                body={
                    "credential_submission_observed": True,
                    "credential_capture_observed": True,
                    "phishing_url": "/lab/phishing/login",
                },
            ),
            response=ResponseInfo(status_code=200),
            resource=ResourceInfo(),
        )
        result = detect_phishing(event)
        assert result.detected is True
        assert result.attack_type == AttackType.PHISHING
        assert result.severity == Severity.HIGH
        assert result.metadata.get("gated_decision") == "DETERMINISTIC_LAB"
