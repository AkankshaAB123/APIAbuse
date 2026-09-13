
import unittest

from dataclasses import replace

from api_detection.backend_adapter import run_for_backend

from api_detection.contracts import (
    ApiSecurityEvent,
    AttackType,
    DetectorDomain,
    DetectorResult,
    EndpointInfo,
    Evidence,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResourceInfo,
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
    detect_security_misconfiguration,
    detect_sql_injection,
    detect_ssrf,
    detect_ddos,
    detect_dos_flooding,
    detect_network_brute_force,
    detect_port_scanning,
    detect_suspicious_process_execution,
    detect_reverse_shell,
    detect_privilege_escalation,
)

from api_detection.detectors.keylogging import detect_keylogging


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

    def test_existing_api_event_remains_compatible(self) -> None:
        event = normal_event()

        self.assertIsNone(event.endpoint)

        self.assertEqual(
            event.network.source_ip,
            "192.168.1.10",
        )

    def test_api_event_accepts_optional_endpoint_telemetry(self) -> None:
        base_event = normal_event()

        endpoint = EndpointInfo(
            event_type="process_activity",
            process_name="powershell.exe",
        )

        event = replace(
            base_event,
            endpoint=endpoint,
        )

        self.assertIsNotNone(event.endpoint)

        self.assertEqual(
            event.endpoint.process_name,
            "powershell.exe",
        )

    def test_endpoint_info_accepts_endpoint_telemetry(self) -> None:
        endpoint = EndpointInfo(
            event_type="process_activity",
            hostname="demo-host",
            username="demo-user",
            process_name="powershell.exe",
            process_id=1234,
            parent_process="winword.exe",
            executable_path=r"C:\Users\demo\AppData\Local\Temp\demo.exe",
            command_line="powershell.exe -Command demo",
            privilege_level="user",
            keyboard_hook=True,
            network_connection=True,
            elevated=False,
        )

        self.assertEqual(
            endpoint.event_type,
            "process_activity",
        )

        self.assertEqual(
            endpoint.process_name,
            "powershell.exe",
        )

        self.assertEqual(
            endpoint.parent_process,
            "winword.exe",
        )

        self.assertTrue(endpoint.keyboard_hook)

        self.assertTrue(endpoint.network_connection)

        self.assertFalse(endpoint.elevated)

    def test_detector_result_defaults_to_api_domain(self) -> None:
        result = DetectorResult(
            event_id="evt-api-domain-001",
            detector_id="bola_idor",
            detected=True,
            attack_type=AttackType.BOLA_IDOR,
            confidence=0.95,
            severity=Severity.HIGH,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.API,
        )

        payload = result.to_dict()

        self.assertEqual(
            payload["domain"],
            "API",
        )

    def test_detector_result_supports_network_domain(self) -> None:
        result = DetectorResult(
            event_id="evt-network-domain-001",
            detector_id="port_scanning",
            detected=True,
            attack_type=AttackType.PORT_SCANNING,
            confidence=0.95,
            severity=Severity.HIGH,
            domain=DetectorDomain.NETWORK,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.NETWORK,
        )

        self.assertEqual(
            result.to_dict()["domain"],
            "NETWORK",
        )

    def test_detector_result_supports_endpoint_domain(self) -> None:
        result = DetectorResult(
            event_id="evt-endpoint-domain-001",
            detector_id="keylogging",
            detected=True,
            attack_type=AttackType.KEYLOGGING,
            confidence=0.94,
            severity=Severity.HIGH,
            domain=DetectorDomain.ENDPOINT,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

        self.assertEqual(
            result.to_dict()["domain"],
            "ENDPOINT",
        )

    # --------------------------------------------------
    # BOLA / IDOR
    # --------------------------------------------------

    # --------------------------------------------------
    # BOLA / IDOR - POSITIVE TESTS
    # --------------------------------------------------

    def test_bola_idor_detects_a_resource_owner_mismatch(self) -> None:
        """1. Authenticated user accessing another user's sensitive resource."""
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
            result.confidence,
            0.97,
        )
        self.assertEqual(
            result.evidence[0].code,
            "RESOURCE_OWNER_MISMATCH",
        )
        self.assertIn("user_17", result.evidence[0].message)
        self.assertIn("user_42", result.evidence[0].message)
        self.assertIn("order 42", result.evidence[0].message)
        self.assertIn("Ownership mismatch", result.evidence[0].message)

    def test_bola_idor_detects_non_sensitive_resource_mismatch(self) -> None:
        """2. Authenticated user accessing another user's non-sensitive resource."""
        event = replace(
            normal_event("evt-bola-nonsensitive"),
            resource=ResourceInfo(
                resource_type="document",
                resource_id="doc_101",
                owner_id="user_42",
                is_sensitive=False,
            ),
        )
        result = detect_bola_idor(event)

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.BOLA_IDOR)
        self.assertEqual(result.severity, Severity.HIGH)
        self.assertEqual(result.confidence, 0.97)
        self.assertEqual(result.evidence[0].code, "RESOURCE_OWNER_MISMATCH")
        self.assertIn("document doc_101", result.evidence[0].message)

    def test_bola_idor_detects_nested_request_ownership_info(self) -> None:
        """3. Resource ownership resolved from request payload context."""
        event = replace(
            normal_event("evt-bola-nested"),
            request=RequestInfo(
                method="POST",
                endpoint="/api/orders/transfer",
                body={
                    "target_user_id": "user_42",
                    "object_id": "transfer_789",
                },
            ),
            resource=ResourceInfo(
                resource_type="order",
                resource_id=None,
                owner_id=None,
                is_sensitive=True,
            ),
        )
        result = detect_bola_idor(event)

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.BOLA_IDOR)
        self.assertEqual(result.severity, Severity.CRITICAL)
        self.assertEqual(result.confidence, 0.97)
        self.assertEqual(result.evidence[0].code, "RESOURCE_OWNER_MISMATCH")
        self.assertIn("user_17", result.evidence[0].message)
        self.assertIn("user_42", result.evidence[0].message)

    def test_bola_idor_detects_different_non_privileged_users_accessing_same_resource(self) -> None:
        """4. Different non-privileged users attempting to access the same owned resource."""
        shared_resource = ResourceInfo(
            resource_type="account",
            resource_id="acc_999",
            owner_id="victim_user",
            is_sensitive=True,
        )

        for attacker_id in ["attacker_alpha", "attacker_beta", "attacker_gamma"]:
            event = replace(
                normal_event(f"evt-bola-{attacker_id}"),
                identity=IdentityInfo(
                    user_id=attacker_id,
                    roles=("customer",),
                    is_authenticated=True,
                ),
                resource=shared_resource,
            )
            result = detect_bola_idor(event)

            self.assertTrue(result.detected, f"Failed to detect BOLA for {attacker_id}")
            self.assertEqual(result.attack_type, AttackType.BOLA_IDOR)
            self.assertEqual(result.confidence, 0.97)
            self.assertEqual(result.severity, Severity.CRITICAL)
            self.assertEqual(result.evidence[0].code, "RESOURCE_OWNER_MISMATCH")
            self.assertIn(attacker_id, result.evidence[0].message)
            self.assertIn("victim_user", result.evidence[0].message)

    # --------------------------------------------------
    # BOLA / IDOR - NEGATIVE TESTS
    # --------------------------------------------------

    def test_bola_idor_ignores_a_user_accessing_own_resource(
        self,
    ) -> None:
        """1. User accessing their own resource."""
        result = detect_bola_idor(
            normal_event()
        )

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_bola_idor_ignores_unauthenticated_request(self) -> None:
        """2. Unauthenticated request (not BOLA)."""
        event = replace(
            bola_idor_event("evt-unauth-bola"),
            identity=IdentityInfo(
                user_id=None,
                roles=(),
                is_authenticated=False,
            ),
        )
        result = detect_bola_idor(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_bola_idor_ignores_admin_role(self) -> None:
        """3. Admin accessing another user's resource."""
        event = replace(
            bola_idor_event("evt-admin-access"),
            identity=IdentityInfo(
                user_id="admin_master",
                roles=("admin",),
                is_authenticated=True,
            ),
        )
        result = detect_bola_idor(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_bola_idor_ignores_service_role(self) -> None:
        """4. Service role accessing another user's resource."""
        event = replace(
            bola_idor_event("evt-service-access"),
            identity=IdentityInfo(
                user_id="svc_order_processor",
                roles=("service",),
                is_authenticated=True,
            ),
        )
        result = detect_bola_idor(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_bola_idor_ignores_missing_user_id(self) -> None:
        """5. Missing user_id."""
        event = replace(
            bola_idor_event("evt-missing-user"),
            identity=IdentityInfo(
                user_id=None,
                roles=("customer",),
                is_authenticated=True,
            ),
        )
        result = detect_bola_idor(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_bola_idor_ignores_missing_owner_id(self) -> None:
        """6. Missing owner_id."""
        event = replace(
            normal_event("evt-missing-owner"),
            resource=ResourceInfo(
                resource_type="order",
                resource_id="42",
                owner_id=None,
            ),
        )
        result = detect_bola_idor(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_bola_idor_ignores_same_user_and_owner(self) -> None:
        """7. Same user and owner."""
        event = replace(
            normal_event("evt-same-owner"),
            identity=IdentityInfo(
                user_id="user_42",
                roles=("customer",),
                is_authenticated=True,
            ),
            resource=ResourceInfo(
                resource_type="profile",
                resource_id="prof_42",
                owner_id="user_42",
            ),
        )
        result = detect_bola_idor(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_bola_idor_ignores_public_non_owned_resource(self) -> None:
        """8. Public or unowned resource."""
        for non_owner in ["public", "system", "none", "unowned", "anonymous"]:
            event = replace(
                normal_event("evt-public-res"),
                resource=ResourceInfo(
                    resource_type="public_catalog",
                    resource_id="cat_1",
                    owner_id=non_owner,
                ),
            )
            result = detect_bola_idor(event)

            self.assertFalse(result.detected, f"Should ignore non-owned identifier: {non_owner}")
            self.assertIsNone(result.attack_type)
            self.assertEqual(result.confidence, 0.0)
            self.assertEqual(result.severity, Severity.LOW)
            self.assertEqual(len(result.evidence), 0)

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
    # SQL Injection - POSITIVE TESTS
    # --------------------------------------------------

    def test_sql_injection_detects_suspicious_query_parameter(
        self,
    ) -> None:
        """1. Existing boolean tautology payload."""
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
        self.assertIn("query_params.query", result.evidence[0].message)
        self.assertEqual(result.confidence, 0.96)
        self.assertEqual(result.severity, Severity.HIGH)

    def test_sql_injection_detects_union_select(
        self,
    ) -> None:
        """2. UNION SELECT payload."""
        event = replace(
            normal_event("evt-sqli-union"),
            request=RequestInfo(
                method="GET",
                endpoint="/api/products",
                query_params={
                    "category": "books UNION SELECT id, username, password FROM users",
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SQL_INJECTION)
        self.assertEqual(result.evidence[0].code, "UNION_SELECT")
        self.assertIn("query_params.category", result.evidence[0].message)
        self.assertEqual(result.confidence, 0.96)
        self.assertEqual(result.severity, Severity.HIGH)

    def test_sql_injection_detects_sql_comment_in_sql_context(
        self,
    ) -> None:
        """3. SQL comment in SQL context."""
        event = replace(
            normal_event("evt-sqli-comment"),
            request=RequestInfo(
                method="POST",
                endpoint="/api/login",
                body={
                    "username": "admin' --",
                    "password": "any",
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SQL_INJECTION)
        self.assertEqual(result.evidence[0].code, "SQL_COMMENT")
        self.assertIn("body.username", result.evidence[0].message)
        self.assertEqual(result.confidence, 0.96)
        self.assertEqual(result.severity, Severity.HIGH)

    def test_sql_injection_detects_information_schema(
        self,
    ) -> None:
        """4. information_schema database metadata inspection."""
        event = replace(
            normal_event("evt-sqli-schema"),
            request=RequestInfo(
                method="GET",
                endpoint="/api/items",
                query_params={
                    "filter": "information_schema.tables",
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SQL_INJECTION)
        self.assertEqual(result.evidence[0].code, "DATABASE_METADATA")
        self.assertIn("query_params.filter", result.evidence[0].message)
        self.assertEqual(result.confidence, 0.96)
        self.assertEqual(result.severity, Severity.HIGH)

    def test_sql_injection_detects_encoded_payload(
        self,
    ) -> None:
        """5. URL-percent encoded SQL injection payload."""
        event = replace(
            normal_event("evt-sqli-encoded"),
            request=RequestInfo(
                method="GET",
                endpoint="/api/search",
                query_params={
                    "q": "%27%20OR%201%3D1",
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SQL_INJECTION)
        self.assertEqual(result.evidence[0].code, "BOOLEAN_TAUTOLOGY")
        self.assertIn("query_params.q", result.evidence[0].message)
        self.assertEqual(result.confidence, 0.96)
        self.assertEqual(result.severity, Severity.HIGH)

    def test_sql_injection_detects_nested_json_body(
        self,
    ) -> None:
        """6. Nested JSON body SQL injection."""
        event = replace(
            normal_event("evt-sqli-nested"),
            request=RequestInfo(
                method="POST",
                endpoint="/api/orders/filter",
                body={
                    "filter": {
                        "criteria": {
                            "clause": "DROP TABLE orders",
                        },
                    },
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SQL_INJECTION)
        self.assertEqual(result.evidence[0].code, "DATA_MANIPULATION")
        self.assertIn("body.filter.criteria.clause", result.evidence[0].message)
        self.assertEqual(result.confidence, 0.96)
        self.assertEqual(result.severity, Severity.HIGH)

    def test_sql_injection_detects_path_parameter(
        self,
    ) -> None:
        """7. Path parameter SQL injection."""
        event = replace(
            normal_event("evt-sqli-path"),
            request=RequestInfo(
                method="GET",
                endpoint="/api/users/1' OR 1=1/profile",
                path_params={
                    "user_id": "1' OR 1=1",
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SQL_INJECTION)
        self.assertEqual(result.evidence[0].code, "BOOLEAN_TAUTOLOGY")
        self.assertIn("path_params.user_id", result.evidence[0].message)
        self.assertEqual(result.confidence, 0.96)
        self.assertEqual(result.severity, Severity.HIGH)

    def test_sql_injection_detects_time_based_delay(
        self,
    ) -> None:
        """8. Time-based SQLi delay indicators: WAITFOR DELAY, SLEEP, pg_sleep."""
        time_payloads = [
            ("1; WAITFOR DELAY '0:0:5'", "query_params.id"),
            ("1 AND SLEEP(5)", "query_params.id"),
            ("1; SELECT pg_sleep(5)", "query_params.id"),
        ]

        for payload, expected_field in time_payloads:
            event = replace(
                normal_event("evt-sqli-time"),
                request=RequestInfo(
                    method="GET",
                    endpoint="/api/items",
                    query_params={
                        "id": payload,
                    },
                ),
            )
            result = detect_sql_injection(event)

            self.assertTrue(result.detected, f"Failed to detect time-based payload: {payload}")
            self.assertEqual(result.attack_type, AttackType.SQL_INJECTION)
            self.assertEqual(result.evidence[0].code, "TIME_BASED")
            self.assertIn(expected_field, result.evidence[0].message)
            self.assertEqual(result.confidence, 0.96)
            self.assertEqual(result.severity, Severity.HIGH)

    # --------------------------------------------------
    # SQL Injection - NEGATIVE TESTS
    # --------------------------------------------------

    def test_sql_injection_ignores_normal_request_values(
        self,
    ) -> None:
        """Baseline normal event."""
        result = detect_sql_injection(
            normal_event()
        )

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_sql_injection_ignores_normal_search_query(
        self,
    ) -> None:
        """1. Normal search query."""
        event = replace(
            normal_event("evt-norm-search"),
            request=RequestInfo(
                method="GET",
                endpoint="/api/products/search",
                query_params={
                    "query": "laptop computer monitor",
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_sql_injection_ignores_normal_text_with_hyphen(
        self,
    ) -> None:
        """2. Normal text containing a hyphen/dash."""
        event = replace(
            normal_event("evt-norm-hyphen"),
            request=RequestInfo(
                method="GET",
                endpoint="/api/catalog",
                query_params={
                    "item": "high-performance semi-automatic widget",
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_sql_injection_ignores_uuid_with_hyphens(
        self,
    ) -> None:
        """3. UUID-like values containing hyphens."""
        event = replace(
            normal_event("evt-norm-uuid"),
            request=RequestInfo(
                method="GET",
                endpoint="/api/devices/f47ac10b-58cc-4372-a567-0e02b2c3d479",
                path_params={
                    "device_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_sql_injection_ignores_ordinary_double_dash_text(
        self,
    ) -> None:
        """4. Ordinary '--' text that is not SQL context."""
        event = replace(
            normal_event("evt-norm-doubledash"),
            request=RequestInfo(
                method="POST",
                endpoint="/api/notes",
                body={
                    "title": "Project Update -- Q3 Review",
                    "cli_flags": "--verbose --dry-run",
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_sql_injection_ignores_normal_json_body(
        self,
    ) -> None:
        """5. Normal JSON body."""
        event = replace(
            normal_event("evt-norm-body"),
            request=RequestInfo(
                method="POST",
                endpoint="/api/users",
                body={
                    "name": "Alice Smith",
                    "email": "alice@example.com",
                    "roles": ["developer", "reviewer"],
                    "profile": {
                        "age": 28,
                        "bio": "Software engineer working on distributed systems.",
                    },
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

    def test_sql_injection_ignores_normal_url_path(
        self,
    ) -> None:
        """6. Normal URL/path."""
        event = replace(
            normal_event("evt-norm-path"),
            request=RequestInfo(
                method="GET",
                endpoint="/api/v1/organizations/corp-123/departments/eng-456/members",
                path_params={
                    "org_id": "corp-123",
                    "dept_id": "eng-456",
                },
            ),
        )
        result = detect_sql_injection(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(len(result.evidence), 0)

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
                    "callback_url": "https://example.com/webhook",
                },
            ),
        )

        result = detect_ssrf(
            public_url_event
        )

        self.assertFalse(result.detected)

    # --------------------------------------------------
    # SSRF - Additional Tests
    # --------------------------------------------------

    def test_ssrf_detects_localhost(self):
        event = replace(
            normal_event(),
            request=replace(
                normal_event().request,
                body={"callback_url": "http://localhost/"},
            ),
        )
        result = detect_ssrf(event)
        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SSRF)
        self.assertEqual(result.evidence[0].code, "LOOPBACK_TARGET")

    def test_ssrf_detects_ipv4_loopback(self):
        event = replace(
            normal_event(),
            request=replace(
                normal_event().request,
                body={"callback_url": "http://127.0.0.1/"},
            ),
        )
        result = detect_ssrf(event)
        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SSRF)
        self.assertEqual(result.evidence[0].code, "LOOPBACK_TARGET")

    def test_ssrf_detects_ipv6_loopback(self):
        event = replace(
            normal_event(),
            request=replace(
                normal_event().request,
                body={"callback_url": "http://[::1]/"},
            ),
        )
        result = detect_ssrf(event)
        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SSRF)
        self.assertEqual(result.evidence[0].code, "LOOPBACK_TARGET")

    def test_ssrf_detects_private_ipv4(self):
        event = replace(
            normal_event(),
            request=replace(
                normal_event().request,
                body={"callback_url": "http://10.0.0.5/"},
            ),
        )
        result = detect_ssrf(event)
        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SSRF)
        self.assertEqual(result.evidence[0].code, "PRIVATE_NETWORK_TARGET")

    def test_ssrf_detects_percent_encoded(self):
        event = replace(
            normal_event(),
            request=replace(
                normal_event().request,
                body={"callback_url": "%68%74%74%70%3A%2F%2F%31%36%39%2E%32%35%34%2E%31%36%39%2E%32%35%34%2F"},
            ),
        )
        result = detect_ssrf(event)
        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SSRF)
        self.assertEqual(result.evidence[0].code, "CLOUD_METADATA_TARGET")

    def test_ssrf_detects_scheme_less_url(self):
        event = replace(
            normal_event(),
            request=replace(
                normal_event().request,
                body={"callback_url": "169.254.169.254/latest/meta-data/"},
            ),
        )
        result = detect_ssrf(event)
        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SSRF)
        self.assertEqual(result.evidence[0].code, "CLOUD_METADATA_TARGET")

    def test_ssrf_detects_restricted_protocol(self):
        event = replace(
            normal_event(),
            request=replace(
                normal_event().request,
                body={"callback_url": "file:///etc/passwd"},
            ),
        )
        result = detect_ssrf(event)
        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.SSRF)
        self.assertEqual(result.evidence[0].code, "RESTRICTED_PROTOCOL_TARGET")
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
    # Security Misconfiguration
    # --------------------------------------------------

    def test_security_misconfiguration_detects_exposed_debug_endpoint(
        self,
    ) -> None:
        event = normal_event()

        misconfigured_event = replace(
            event,
            event_id="evt-misconfiguration-001",
            request=replace(
                event.request,
                endpoint="/api/debug/config",
            ),
        )

        result = detect_security_misconfiguration(
            misconfigured_event
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.SECURITY_MISCONFIGURATION,
        )

        self.assertEqual(
            result.evidence[0].code,
            "EXPOSED_CONFIGURATION_ENDPOINT",
        )

    def test_security_misconfiguration_ignores_normal_endpoint(
        self,
    ) -> None:
        result = detect_security_misconfiguration(
            normal_event()
        )

        self.assertFalse(result.detected)

        self.assertIsNone(
            result.attack_type
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
    # DDoS
    # --------------------------------------------------

    def test_ddos_detects_distributed_request_flood(
        self,
    ) -> None:
        base_event = normal_event()

        history = [
            replace(
                base_event,
                event_id=f"evt-ddos-{number}",
                network=replace(
                    base_event.network,
                    source_ip=f"192.0.2.{number}",
                    destination_ip="198.51.100.10",
                ),
            )
            for number in range(1, 100)
        ]

        current_event = replace(
            base_event,
            event_id="evt-ddos-100",
            network=replace(
                base_event.network,
                source_ip="192.0.2.100",
                destination_ip="198.51.100.10",
            ),
        )

        result = detect_ddos(
            current_event,
            history,
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.DDOS,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.NETWORK,
        )

    def test_ddos_ignores_low_volume_traffic(
        self,
    ) -> None:
        base_event = normal_event()

        history = [
            replace(
                base_event,
                event_id=f"evt-ddos-normal-{number}",
                network=replace(
                    base_event.network,
                    source_ip=f"192.0.2.{number}",
                    destination_ip="198.51.100.10",
                ),
            )
            for number in range(1, 5)
        ]

        current_event = replace(
            base_event,
            event_id="evt-ddos-normal-5",
            network=replace(
                base_event.network,
                source_ip="192.0.2.5",
                destination_ip="198.51.100.10",
            ),
        )

        result = detect_ddos(
            current_event,
            history,
        )

        self.assertFalse(result.detected)

        self.assertIsNone(result.attack_type)

        self.assertEqual(
            result.domain,
            DetectorDomain.NETWORK,
        )

    # --------------------------------------------------
    # DoS / Flooding
    # --------------------------------------------------

    def test_dos_flooding_detects_high_request_volume(
        self,
    ) -> None:
        base_event = normal_event()

        history = [
            replace(
                base_event,
                event_id=f"evt-dos-{number}",
                network=replace(
                    base_event.network,
                    source_ip="192.0.2.50",
                    destination_ip="198.51.100.20",
                ),
            )
            for number in range(1, 100)
        ]

        current_event = replace(
            base_event,
            event_id="evt-dos-100",
            network=replace(
                base_event.network,
                source_ip="192.0.2.50",
                destination_ip="198.51.100.20",
            ),
        )

        result = detect_dos_flooding(
            current_event,
            history,
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.DOS_FLOODING,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.NETWORK,
        )

    def test_dos_flooding_ignores_low_request_volume(
        self,
    ) -> None:
        base_event = normal_event()

        history = [
            replace(
                base_event,
                event_id=f"evt-dos-normal-{number}",
                network=replace(
                    base_event.network,
                    source_ip="192.0.2.50",
                    destination_ip="198.51.100.20",
                ),
            )
            for number in range(1, 5)
        ]

        current_event = replace(
            base_event,
            event_id="evt-dos-normal-5",
            network=replace(
                base_event.network,
                source_ip="192.0.2.50",
                destination_ip="198.51.100.20",
            ),
        )

        result = detect_dos_flooding(
            current_event,
            history,
        )

        self.assertFalse(result.detected)

        self.assertIsNone(result.attack_type)

        self.assertEqual(
            result.domain,
            DetectorDomain.NETWORK,
        )

    # --------------------------------------------------
    # Port Scanning
    # --------------------------------------------------

    def test_port_scanning_detects_many_destination_ports(
        self,
    ) -> None:
        base_event = normal_event()

        history = [
            replace(
                base_event,
                event_id=f"evt-port-scan-{port}",
                network=replace(
                    base_event.network,
                    source_ip="192.0.2.60",
                    destination_ip="198.51.100.30",
                    destination_port=port,
                ),
            )
            for port in range(1, 100)
        ]

        current_event = replace(
            base_event,
            event_id="evt-port-scan-100",
            network=replace(
                base_event.network,
                source_ip="192.0.2.60",
                destination_ip="198.51.100.30",
                destination_port=100,
            ),
        )

        result = detect_port_scanning(
            current_event,
            history,
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.PORT_SCANNING,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.NETWORK,
        )

    def test_port_scanning_ignores_few_destination_ports(
        self,
    ) -> None:
        base_event = normal_event()

        history = [
            replace(
                base_event,
                event_id=f"evt-port-normal-{port}",
                network=replace(
                    base_event.network,
                    source_ip="192.0.2.60",
                    destination_ip="198.51.100.30",
                    destination_port=port,
                ),
            )
            for port in range(1, 4)
        ]

        current_event = replace(
            base_event,
            event_id="evt-port-normal-4",
            network=replace(
                base_event.network,
                source_ip="192.0.2.60",
                destination_ip="198.51.100.30",
                destination_port=4,
            ),
        )

        result = detect_port_scanning(
            current_event,
            history,
        )

        self.assertFalse(result.detected)

        self.assertIsNone(result.attack_type)

        self.assertEqual(
            result.domain,
            DetectorDomain.NETWORK,
        )

    # --------------------------------------------------
    # Network Brute Force
    # --------------------------------------------------

    def test_network_brute_force_detects_repeated_failed_connections(
        self,
    ) -> None:
        base_event = normal_event()

        history = [
            replace(
                base_event,
                event_id=f"evt-network-brute-{number}",
                network=replace(
                    base_event.network,
                    source_ip="192.0.2.70",
                    destination_ip="198.51.100.40",
                    destination_port=22,
                    connection_status="failed",
                ),
            )
            for number in range(1, 10)
        ]

        current_event = replace(
            base_event,
            event_id="evt-network-brute-10",
            network=replace(
                base_event.network,
                source_ip="192.0.2.70",
                destination_ip="198.51.100.40",
                destination_port=22,
                connection_status="failed",
            ),
        )

        result = detect_network_brute_force(
            current_event,
            history,
        )

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.NETWORK_BRUTE_FORCE,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.NETWORK,
        )

    def test_network_brute_force_ignores_few_failed_connections(
        self,
    ) -> None:
        base_event = normal_event()

        history = [
            replace(
                base_event,
                event_id=f"evt-network-brute-normal-{number}",
                network=replace(
                    base_event.network,
                    source_ip="192.0.2.70",
                    destination_ip="198.51.100.40",
                    destination_port=22,
                    connection_status="failed",
                ),
            )
            for number in range(1, 3)
        ]

        current_event = replace(
            base_event,
            event_id="evt-network-brute-normal-3",
            network=replace(
                base_event.network,
                source_ip="192.0.2.70",
                destination_ip="198.51.100.40",
                destination_port=22,
                connection_status="failed",
            ),
        )

        result = detect_network_brute_force(
            current_event,
            history,
        )

        self.assertFalse(result.detected)

        self.assertIsNone(result.attack_type)

        self.assertEqual(
            result.domain,
            DetectorDomain.NETWORK,
        )

    # --------------------------------------------------
    # Keylogging
    # --------------------------------------------------

    def test_keylogging_detects_keyboard_hook(self) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="keyboard_activity",
                hostname="host-01",
                username="alice",
                process_name="suspicious.exe",
                process_id=1234,
                keyboard_hook=True,
            ),
        )

        result = detect_keylogging(event)

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.KEYLOGGING,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

        self.assertEqual(
            result.detector_id,
            "keylogging",
        )

        self.assertEqual(
            result.severity,
            Severity.HIGH,
        )

        self.assertEqual(
            len(result.evidence),
            1,
        )

    def test_keylogging_ignores_no_keyboard_hook(self) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="keyboard_activity",
                hostname="host-01",
                username="alice",
                process_name="normal.exe",
                process_id=1234,
                keyboard_hook=False,
            ),
        )

        result = detect_keylogging(event)

        self.assertFalse(result.detected)

        self.assertIsNone(result.attack_type)

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

    def test_keylogging_ignores_missing_endpoint_telemetry(self) -> None:
        event = replace(
            normal_event(),
            endpoint=None,
        )

        result = detect_keylogging(event)

        self.assertFalse(result.detected)

        self.assertIsNone(result.attack_type)

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )
        # --------------------------------------------------
    # Suspicious Process Execution
    # --------------------------------------------------

    def test_suspicious_process_execution_detects_suspicious_process(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="process_activity",
                hostname="host-01",
                username="alice",
                process_name="powershell.exe",
                process_id=4321,
                parent_process="winword.exe",
                executable_path=(
                    r"C:\Windows\System32\WindowsPowerShell\v1.0"
                    r"\powershell.exe"
                ),
                command_line="powershell.exe -NoProfile -ExecutionPolicy Bypass",
            ),
        )

        result = detect_suspicious_process_execution(event)

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.SUSPICIOUS_PROCESS_EXECUTION,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

        self.assertEqual(
            result.detector_id,
            "suspicious_process_execution",
        )

        self.assertEqual(
            result.severity,
            Severity.HIGH,
        )

        self.assertEqual(
            len(result.evidence),
            2,
        )

    def test_suspicious_process_execution_detects_suspicious_command(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="process_activity",
                hostname="host-02",
                username="alice",
                process_name="custom-tool.exe",
                process_id=5678,
                command_line="custom-tool.exe -EncodedCommand ABC123",
            ),
        )

        result = detect_suspicious_process_execution(event)

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.SUSPICIOUS_PROCESS_EXECUTION,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

        self.assertEqual(
            result.evidence[0].code,
            "SUSPICIOUS_COMMAND_LINE",
        )

    def test_suspicious_process_execution_ignores_normal_process(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="process_activity",
                hostname="host-03",
                username="alice",
                process_name="notepad.exe",
                process_id=6789,
                parent_process="explorer.exe",
                executable_path=(
                    r"C:\Windows\System32\notepad.exe"
                ),
                command_line="notepad.exe document.txt",
            ),
        )

        result = detect_suspicious_process_execution(event)

        self.assertFalse(result.detected)

        self.assertIsNone(result.attack_type)

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

    def test_suspicious_process_execution_ignores_missing_endpoint(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=None,
        )

        result = detect_suspicious_process_execution(event)

        self.assertFalse(result.detected)

        self.assertIsNone(result.attack_type)

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )
        # --------------------------------------------------
    # Reverse Shell
    # --------------------------------------------------

    def test_reverse_shell_detects_shell_with_network_connection(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="process_activity",
                hostname="host-01",
                username="alice",
                process_name="bash",
                process_id=4321,
                parent_process="python.exe",
                command_line="bash -i",
                network_connection=True,
            ),
        )

        result = detect_reverse_shell(event)

        self.assertTrue(result.detected)
        self.assertEqual(
            result.attack_type,
            AttackType.REVERSE_SHELL,
        )
        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )
        self.assertEqual(
            result.detector_id,
            "reverse_shell",
        )
        self.assertEqual(
            result.severity,
            Severity.CRITICAL,
        )
        self.assertEqual(len(result.evidence), 3)

    def test_reverse_shell_detects_suspicious_command_with_network_connection(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="process_activity",
                hostname="host-02",
                username="alice",
                process_name="custom-tool.exe",
                process_id=5678,
                command_line="custom-tool.exe nc 192.0.2.10 4444",
                network_connection=True,
            ),
        )

        result = detect_reverse_shell(event)

        self.assertTrue(result.detected)
        self.assertEqual(
            result.attack_type,
            AttackType.REVERSE_SHELL,
        )
        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

    def test_reverse_shell_ignores_single_weak_signal(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="process_activity",
                hostname="host-03",
                username="alice",
                process_name="bash",
                process_id=6789,
                network_connection=False,
            ),
        )

        result = detect_reverse_shell(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

    def test_reverse_shell_ignores_normal_process_without_network_activity(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="process_activity",
                hostname="host-04",
                username="alice",
                process_name="notepad.exe",
                process_id=7890,
                parent_process="explorer.exe",
                command_line="notepad.exe document.txt",
                network_connection=False,
            ),
        )

        result = detect_reverse_shell(event)

        self.assertFalse(result.detected)
        self.assertIsNone(result.attack_type)
        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )
        # --------------------------------------------------
    # Privilege Escalation
    # --------------------------------------------------

    def test_privilege_escalation_detects_command_with_elevated_context(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="process_activity",
                hostname="host-05",
                username="alice",
                process_name="sudo",
                process_id=8001,
                parent_process="bash",
                command_line="sudo service-status",
                privilege_level="admin",
                elevated=True,
            ),
        )

        result = detect_privilege_escalation(event)

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.PRIVILEGE_ESCALATION,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

        self.assertEqual(
            result.detector_id,
            "privilege_escalation",
        )

        self.assertEqual(
            result.severity,
            Severity.CRITICAL,
        )

        self.assertEqual(
            len(result.evidence),
            3,
        )

    def test_privilege_escalation_detects_privileged_context_with_elevated_flag(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="process_activity",
                hostname="host-06",
                username="alice",
                process_name="admin-tool.exe",
                process_id=8002,
                privilege_level="administrator",
                elevated=True,
            ),
        )

        result = detect_privilege_escalation(event)

        self.assertTrue(result.detected)

        self.assertEqual(
            result.attack_type,
            AttackType.PRIVILEGE_ESCALATION,
        )

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

        self.assertEqual(
            result.detector_id,
            "privilege_escalation",
        )

    def test_privilege_escalation_ignores_single_signal(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="process_activity",
                hostname="host-07",
                username="alice",
                process_name="admin-tool.exe",
                process_id=8003,
                privilege_level="administrator",
                elevated=False,
            ),
        )

        result = detect_privilege_escalation(event)

        self.assertFalse(result.detected)

        self.assertIsNone(result.attack_type)

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

    def test_privilege_escalation_ignores_normal_process(
        self,
    ) -> None:
        event = replace(
            normal_event(),
            endpoint=EndpointInfo(
                event_type="process_activity",
                hostname="host-08",
                username="alice",
                process_name="notepad.exe",
                process_id=8004,
                parent_process="explorer.exe",
                command_line="notepad.exe document.txt",
                privilege_level="user",
                elevated=False,
            ),
        )

        result = detect_privilege_escalation(event)

        self.assertFalse(result.detected)

        self.assertIsNone(result.attack_type)

        self.assertEqual(
            result.domain,
            DetectorDomain.ENDPOINT,
        )

    # --------------------------------------------------
    # Engine
    # --------------------------------------------------


    def test_engine_returns_all_20_registered_detector_results(
        self,
    ) -> None:
        results = run_all_detectors(
            bola_idor_event()
        )

        # Engine now has 20 registered detectors:
        # API (12): bola_idor, broken_function_level_authorization,
        #   credential_attacks, account_takeover, sql_injection, xss,
        #   ssrf, resource_exhaustion, fake_shopping, fake_bank,
        #   endpoint_enumeration, security_misconfiguration
        # Network (4): ddos, dos_flooding, port_scanning, network_brute_force
        # Endpoint (4): keylogging, suspicious_process_execution,
        #   reverse_shell, privilege_escalation
        self.assertEqual(
            len(results),
            20,
        )

        self.assertTrue(
            results[0].detected
        )

        self.assertEqual(
            results[0].detector_id,
            "bola_idor",
        )

        # ddos is at index 12 after xss (5), fake_shopping (8), fake_bank (9)
        # were added to the API detector block
        self.assertEqual(
            results[12].detector_id,
            "ddos",
        )

        self.assertEqual(
            results[13].detector_id,
            "dos_flooding",
        )

        self.assertEqual(
            results[14].detector_id,
            "port_scanning",
        )

        self.assertEqual(
            results[15].detector_id,
            "network_brute_force",
        )

        self.assertEqual(
            results[16].detector_id,
            "keylogging",
        )

        self.assertEqual(
            results[17].detector_id,
            "suspicious_process_execution",
        )

        self.assertEqual(
            results[18].detector_id,
            "reverse_shell",
        )

        self.assertEqual(
            results[19].detector_id,
            "privilege_escalation",
        )


if __name__ == "__main__":
    unittest.main()

