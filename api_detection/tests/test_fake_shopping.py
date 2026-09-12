import unittest

from api_detection.simulator import fake_shopping_event
from api_detection.detectors.fake_shopping import detect_fake_shopping
from api_detection.contracts import AttackType, Severity

class FakeShoppingDetectorTests(unittest.TestCase):
    def test_positive_fake_shopping_detection(self):
        event = fake_shopping_event()
        result = detect_fake_shopping(event)
        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.BUSINESS_FLOW_ABUSE)
        self.assertEqual(result.severity, Severity.HIGH)
        # Ensure evidence code is present
        evidence_codes = [e.code for e in result.evidence]
        self.assertIn("FAKE_SHOPPING_DETECTED", evidence_codes)

    def test_negative_fake_shopping_detection_wrong_payment(self):
        event = fake_shopping_event()
        # modify payment to a non‑matching value
        event.request.body["payment"] = "pending"
        result = detect_fake_shopping(event)
        self.assertFalse(result.detected)

if __name__ == "__main__":
    unittest.main()
