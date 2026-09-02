import unittest
from dataclasses import replace

from api_detection.backend_adapter import run_for_backend
from api_detection.contracts import (
    AttackType,
    DetectorResult,
    Evidence,
    Severity,
)
from api_detection.detectors import (
    detect_account_takeover,
    detect_bola_idor,
    detect_broken_function_level_authorization,
    detect_business_flow_abuse,
    detect_credential_attacks,
    detect_endpoint_enumeration,
    detect_resource_exhaustion,
    detect_sql_injection,
    detect_ssrf,
)
from api_detection.engine import run_all_detectors
from api_detection.simulator import (
    bola_idor_event,
    business_flow_abuse_event,
    endpoint_enumeration_event,
    failed_login_event,
    normal_event,
    privilege_escalation_event,
    resource_exhaustion_event,
    sql_injection_event,
    ssrf_event,
    successful_login_event,
)


class DetectorContractTests(unittest.TestCase):

    # --------------------------------------------------
    # Contract
    # --------------------------------------------------

    def test_result_serializes_to_agreed_contract(self) -> None:
        result = DetectorResult(
            event_id="evt-001",
            detector_id="bola_idor",
            detected=True,
            attack_type=AttackType.BOLA_IDOR,
            confidence=0.94,
            severity=Severity.CRITICAL,
            evidence=(
                Evidence(
                    "RESOURCE_OWNER_MISMATCH",
                    "Owner differs",
                ),
            ),
            metadata={
                "rule_version": "1.0",
                "window_seconds": 0,
            },
        )

        payload = result.to_dict()

        self.assertEqual(
            payload["attack_type"],
            "BOLA_IDOR",
        )
        self.assertEqual(
            payload["severity"],
            "CRITICAL",
        )
        self.assertEqual(
            payload["evidence"][0]["code"],
            "RESOURCE_OWNER_MISMATCH",
        )

    # --------------------------------------------------
    # BOLA / IDOR
    # --------------------------------------------------

    def test_bola_idor_detects_a_resource_owner_mismatch(self) -> None:
        result = detect_bola_idor(
            bola_idor_event()
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.BOLA_IDOR,
        )

        self.assertEqual(
            result.severity,
            Severity.CRITICAL,
        )

        self.assertEqual(
            result.evidence[0].code,
            "RESOURCE_OWNER_MISMATCH",
        )

    def test_bola_idor_ignores_a_user_accessing_own_resource(
        self,
    ) -> None:
        result = detect_bola_idor(
            normal_event()
        )

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)

    # --------------------------------------------------
    # Broken Function Level Authorization
    # --------------------------------------------------

    def test_privilege_escalation_detects_customer_on_admin_route(
        self,
    ) -> None:
        result = (
            detect_broken_function_level_authorization(
                privilege_escalation_event()
            )
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
        )

        self.assertEqual(
            result.severity,
            Severity.CRITICAL,
        )

    def test_privilege_escalation_allows_admin_role(
        self,
    ) -> None:
        event = privilege_escalation_event()

        admin_event = replace(
            event,
            identity=replace(
                event.identity,
                roles=("admin",),
            ),
        )

        result = (
            detect_broken_function_level_authorization(
                admin_event
            )
        )

        self.assertFalse(result.detected)

    # --------------------------------------------------
    # Credential Attacks
    # --------------------------------------------------

    def test_credential_attacks_detect_brute_force(
        self,
    ) -> None:
        history = [
            failed_login_event(
                f"evt-brute-{number}",
                "user_17",
            )
            for number in range(1, 5)
        ]

        current_event = failed_login_event(
            "evt-brute-5",
            "user_17",
        )

        result = detect_credential_attacks(
            current_event,
            history,
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.metadata["subtype"],
            "BRUTE_FORCE",
        )

        self.assertEqual(
            result.metadata["failed_attempts"],
            5,
        )

    def test_credential_attacks_detect_credential_stuffing(
        self,
    ) -> None:
        history = [
            failed_login_event(
                "evt-stuff-1",
                "alice",
            ),
            failed_login_event(
                "evt-stuff-2",
                "bob",
            ),
            failed_login_event(
                "evt-stuff-3",
                "carol",
            ),
            failed_login_event(
                "evt-stuff-4",
                "dave",
            ),
        ]

        current_event = failed_login_event(
            "evt-stuff-5",
            "erin",
        )

        result = detect_credential_attacks(
            current_event,
            history,
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.metadata["subtype"],
            "CREDENTIAL_STUFFING",
        )

        self.assertEqual(
            result.metadata["unique_accounts"],
            5,
        )

    def test_credential_attacks_ignore_an_isolated_failed_login(
        self,
    ) -> None:
        result = detect_credential_attacks(
            failed_login_event(
                "evt-single",
                "user_17",
            )
        )

        self.assertFalse(result.detected)

    # --------------------------------------------------
    # Account Takeover
    # --------------------------------------------------

    def test_account_takeover_detects_failed_logins_then_success(
        self,
    ) -> None:
        history = [
            failed_login_event(
                f"evt-takeover-failed-{number}",
                "user_17",
            )
            for number in range(1, 4)
        ]

        result = detect_account_takeover(
            successful_login_event(),
            history,
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.ACCOUNT_TAKEOVER,
        )

        self.assertEqual(
            result.metadata["subtype"],
            "FAILED_LOGINS_THEN_SUCCESS",
        )

    def test_account_takeover_detects_session_ip_change(
        self,
    ) -> None:
        previous_event = normal_event()

        changed_ip_event = replace(
            previous_event,
            event_id="evt-session-ip-change",
            network=replace(
                previous_event.network,
                source_ip="192.168.1.99",
            ),
        )

        result = detect_account_takeover(
            changed_ip_event,
            [previous_event],
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.metadata["subtype"],
            "SESSION_IP_CHANGE",
        )

    def test_account_takeover_ignores_normal_successful_login(
        self,
    ) -> None:
        result = detect_account_takeover(
            successful_login_event()
        )

        self.assertFalse(result.detected)

    # --------------------------------------------------
    # SQL Injection
    # --------------------------------------------------

    def test_sql_injection_detects_suspicious_query_parameter(
        self,
    ) -> None:
        result = detect_sql_injection(
            sql_injection_event()
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.SQL_INJECTION,
        )

        self.assertEqual(
            result.evidence[0].code,
            "BOOLEAN_TAUTOLOGY",
        )

    def test_sql_injection_ignores_normal_request_values(
        self,
    ) -> None:
        result = detect_sql_injection(
            normal_event()
        )

        self.assertFalse(result.detected)

    # --------------------------------------------------
    # SSRF
    # --------------------------------------------------

    def test_ssrf_detects_cloud_metadata_target(
        self,
    ) -> None:
        result = detect_ssrf(
            ssrf_event()
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.SSRF,
        )

        self.assertEqual(
            result.evidence[0].code,
            "CLOUD_METADATA_TARGET",
        )

    def test_ssrf_ignores_public_url(
        self,
    ) -> None:
        event = normal_event()

        public_url_event = replace(
            event,
            request=replace(
                event.request,
                body={
                    "callback_url":
                        "https://example.com/webhook",
                },
            ),
        )

        result = detect_ssrf(
            public_url_event
        )

        self.assertFalse(result.detected)

    # --------------------------------------------------
    # Resource Exhaustion
    # --------------------------------------------------

    def test_resource_exhaustion_detects_excessive_requests(
        self,
    ) -> None:
        history = [
            resource_exhaustion_event(
                f"evt-resource-{number}"
            )
            for number in range(1, 10)
        ]

        current_event = resource_exhaustion_event(
            "evt-resource-10"
        )

        result = detect_resource_exhaustion(
            current_event,
            history,
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.RESOURCE_EXHAUSTION,
        )

        self.assertEqual(
            result.metadata["request_count"],
            10,
        )

        self.assertEqual(
            result.evidence[0].code,
            "EXCESSIVE_REQUEST_VOLUME",
        )

    def test_resource_exhaustion_ignores_normal_request_volume(
        self,
    ) -> None:
        history = [
            resource_exhaustion_event(
                f"evt-resource-normal-{number}"
            )
            for number in range(1, 5)
        ]

        current_event = resource_exhaustion_event(
            "evt-resource-normal-current"
        )

        result = detect_resource_exhaustion(
            current_event,
            history,
        )

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)

        self.assertEqual(
            result.metadata["request_count"],
            5,
        )

    # --------------------------------------------------
    # Business Flow Abuse
    # --------------------------------------------------

    def test_business_flow_abuse_detects_repeated_sensitive_action(
        self,
    ) -> None:
        history = [
            business_flow_abuse_event(
                f"evt-business-flow-{number}"
            )
            for number in range(1, 5)
        ]

        current_event = business_flow_abuse_event(
            "evt-business-flow-5"
        )

        result = detect_business_flow_abuse(
            current_event,
            history,
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.BUSINESS_FLOW_ABUSE,
        )

    def test_business_flow_abuse_ignores_normal_activity(
        self,
    ) -> None:
        result = detect_business_flow_abuse(
            normal_event()
        )

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)

    # --------------------------------------------------
    # Endpoint Enumeration
    # --------------------------------------------------

    def test_endpoint_enumeration_detects_multiple_endpoints(
        self,
    ) -> None:
        endpoints = [
            "/api/users",
            "/api/orders",
            "/api/products",
            "/api/admin",
        ]

        history = [
            endpoint_enumeration_event(
                f"evt-enumeration-{number}",
                endpoint,
            )
            for number, endpoint in enumerate(
                endpoints,
                start=1,
            )
        ]

        current_event = endpoint_enumeration_event(
            "evt-enumeration-5",
            "/api/payments",
        )

        result = detect_endpoint_enumeration(
            current_event,
            history,
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.ENDPOINT_ENUMERATION,
        )

        self.assertEqual(
            result.metadata["endpoint_count"],
            5,
        )

    def test_endpoint_enumeration_ignores_normal_activity(
        self,
    ) -> None:
        history = [
            endpoint_enumeration_event(
                "evt-enumeration-normal-1",
                "/api/users",
            ),
            endpoint_enumeration_event(
                "evt-enumeration-normal-2",
                "/api/orders",
            ),
        ]

        current_event = endpoint_enumeration_event(
            "evt-enumeration-normal-3",
            "/api/users",
        )

        result = detect_endpoint_enumeration(
            current_event,
            history,
        )

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)

    # --------------------------------------------------
    # Engine
    # --------------------------------------------------

    def test_engine_returns_registered_detector_results(
        self,
    ) -> None:
        results = run_all_detectors(
            bola_idor_event()
        )

        self.assertEqual(
            len(results),
            10,
        )

        self.assertTrue(
            results[0].detected
        )

    # --------------------------------------------------
    # Backend Adapter
    # --------------------------------------------------

    def test_backend_adapter_preserves_contract_and_metadata_details(
        self,
    ) -> None:
        event = {
            "schema_version": "1.0",
            "event_id": "evt-adapter-001",
            "timestamp": "2026-09-02T10:00:00Z",
            "network": {
                "source_ip": "192.168.1.77",
                "user_agent": "demo-client/1.0",
            },
            "identity": {
                "user_id": None,
                "session_id": None,
                "roles": [],
                "is_authenticated": False,
            },
            "request": {
                "method": "POST",
                "endpoint": "/api/auth/login",
                "path_params": {},
                "query_params": {},
                "headers": {},
                "body": {
                    "username": "user_17",
                    "password": "incorrect",
                },
            },
            "response": {
                "status_code": 401,
                "latency_ms": 35.5,
            },
            "resource": {
                "resource_type": None,
                "resource_id": None,
                "owner_id": None,
                "is_sensitive": False,
            },
        }

        history = [
            {
                **event,
                "event_id": (
                    f"evt-adapter-history-{number}"
                ),
            }
            for number in range(1, 5)
        ]

        results = run_for_backend(
            event,
            history,
        )

        credential_result = next(
            result
            for result in results
            if result["detector_id"]
            == "credential_attacks"
        )

        self.assertTrue(
            credential_result["detected"]
        )

        self.assertEqual(
            credential_result["attack_type"],
            "CREDENTIAL_ATTACK",
        )

        self.assertEqual(
            credential_result["metadata"]["window_seconds"],
            300,
        )

        self.assertEqual(
            credential_result["metadata"]["details"]["subtype"],
            "BRUTE_FORCE",
        )


if __name__ == "__main__":
    unittest.main()