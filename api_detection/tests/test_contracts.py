
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
    NetworkInfo,
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
                    "callback_url": "https://example.com/webhook",
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

    
    def test_engine_returns_all_18_registered_detector_results(
        self,
    ) -> None:
        results = run_all_detectors(
            bola_idor_event()
        )

        self.assertEqual(
            len(results),
            18,
        )

        self.assertTrue(
            results[0].detected
        )

        self.assertEqual(
            results[0].detector_id,
            "bola_idor",
        )

        self.assertEqual(
            results[10].detector_id,
            "ddos",
        )

        self.assertEqual(
            results[11].detector_id,
            "dos_flooding",
        )

        self.assertEqual(
            results[12].detector_id,
            "port_scanning",
        )

        self.assertEqual(
            results[13].detector_id,
            "network_brute_force",
        )

        self.assertEqual(
            results[14].detector_id,
            "keylogging",
        )

        self.assertEqual(
            results[15].detector_id,
            "suspicious_process_execution",
        )

        self.assertEqual(
            results[16].detector_id,
            "reverse_shell",
        )

        self.assertEqual(
            results[17].detector_id,
            "privilege_escalation",
        )


if __name__ == "__main__":
    unittest.main()

