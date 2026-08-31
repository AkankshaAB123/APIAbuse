import unittest

from dataclasses import replace

from api_detection.contracts import AttackType, DetectorResult, Evidence, Severity
from api_detection.detectors import (
    detect_bola_idor,
    detect_broken_function_level_authorization,
)
from api_detection.engine import run_all_detectors
from api_detection.simulator import (
    bola_idor_event,
    normal_event,
    privilege_escalation_event,
)


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

    def test_bola_idor_detects_a_resource_owner_mismatch(self) -> None:
        result = detect_bola_idor(bola_idor_event())

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.BOLA_IDOR)
        self.assertEqual(result.severity, Severity.CRITICAL)
        self.assertEqual(result.evidence[0].code, "RESOURCE_OWNER_MISMATCH")

    def test_bola_idor_ignores_a_user_accessing_own_resource(self) -> None:
        result = detect_bola_idor(normal_event())

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)

    def test_privilege_escalation_detects_customer_on_admin_route(self) -> None:
        result = detect_broken_function_level_authorization(privilege_escalation_event())

        self.assertTrue(result.detected)
        self.assertEqual(
            result.attack_type, AttackType.BROKEN_FUNCTION_LEVEL_AUTHORIZATION
        )
        self.assertEqual(result.severity, Severity.CRITICAL)

    def test_privilege_escalation_allows_admin_role(self) -> None:
        event = privilege_escalation_event()
        admin_event = replace(
            event, identity=replace(event.identity, roles=("admin",))
        )

        result = detect_broken_function_level_authorization(admin_event)

        self.assertFalse(result.detected)

    def test_engine_returns_registered_detector_results(self) -> None:
        results = run_all_detectors(bola_idor_event())

        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].detected)


if __name__ == "__main__":
    unittest.main()
