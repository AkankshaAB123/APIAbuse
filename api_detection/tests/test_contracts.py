import unittest

from api_detection.contracts import AttackType, DetectorResult, Evidence, Severity
from api_detection.engine import run_all_detectors
from api_detection.simulator import normal_event


class DetectorContractTests(unittest.TestCase):
    def test_result_serializes_to_agreed_contract(self) -> None:
        result = DetectorResult(
            event_id="evt-001",
            detector_id="bola_idor",
            detected=True,
            attack_type=AttackType.BOLA_IDOR,
            confidence=0.94,
            severity=Severity.CRITICAL,
            evidence=(Evidence("RESOURCE_OWNER_MISMATCH", "Owner differs"),),
            metadata={"rule_version": "1.0", "window_seconds": 0},
        )

        payload = result.to_dict()

        self.assertEqual(payload["attack_type"], "BOLA_IDOR")
        self.assertEqual(payload["severity"], "CRITICAL")
        self.assertEqual(payload["evidence"][0]["code"], "RESOURCE_OWNER_MISMATCH")

    def test_engine_is_safe_before_detectors_are_registered(self) -> None:
        self.assertEqual(run_all_detectors(normal_event()), [])


if __name__ == "__main__":
    unittest.main()
