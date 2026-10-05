"""Tests for LaptopAgent and CLI interface."""

from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, patch

from agents.agent_client import AgentClient, AgentResponse
from agents.laptop_agent import LaptopAgent, main, parse_args
from backend.schemas.api_security_event import ApiSecurityEvent, EndpointInfo


class TestLaptopAgent(unittest.TestCase):
    """Unit and simulation tests for LaptopAgent."""

    def setUp(self) -> None:
        self.mock_client = MagicMock(spec=AgentClient)
        self.agent = LaptopAgent(
            client=self.mock_client,
            hostname="TEST-WORKSTATION",
            username="test_student",
        )

    def test_live_telemetry_returns_valid_endpoint_info(self) -> None:
        """Requirement 1: Verify live telemetry collects safe local metadata without crashing."""
        telemetry = self.agent.collect_telemetry()

        self.assertIsInstance(telemetry, EndpointInfo)
        self.assertEqual(telemetry.hostname, "TEST-WORKSTATION")
        self.assertEqual(telemetry.username, "test_student")
        self.assertIsNotNone(telemetry.process_name)
        self.assertIsNotNone(telemetry.process_id)
        self.assertFalse(telemetry.keyboard_hook)
        self.assertFalse(telemetry.network_connection)
        self.assertIn(telemetry.privilege_level, ("USER", "ADMIN", "ROOT"))
        self.assertIsInstance(telemetry.elevated, bool)

    def test_suspicious_process_simulation_produces_valid_endpoint_event(self) -> None:
        """Requirement 2: Verify suspicious process simulation produces valid telemetry and ENDPOINT event."""
        telemetry = self.agent.simulate_suspicious_process()

        self.assertEqual(telemetry.process_name, "powershell.exe")
        self.assertIn("-enc", telemetry.command_line.lower())
        self.assertEqual(telemetry.event_type, "process_creation")

        event = self.agent.build_event(telemetry)
        self.assertIsInstance(event, ApiSecurityEvent)
        self.assertEqual(event.domain, "ENDPOINT")
        self.assertEqual(event.endpoint.process_name, "powershell.exe")

    def test_keylogging_simulation_produces_keyboard_hook(self) -> None:
        """Requirement 3: Verify keylogging simulation produces keyboard_hook=True."""
        telemetry = self.agent.simulate_keylogging()

        self.assertTrue(telemetry.keyboard_hook)
        self.assertEqual(telemetry.event_type, "keylogger_detected")

        event = self.agent.build_event(telemetry)
        self.assertTrue(event.endpoint.keyboard_hook)
        self.assertEqual(event.domain, "ENDPOINT")

    def test_reverse_shell_simulation_produces_network_connection(self) -> None:
        """Requirement 4: Verify reverse shell simulation produces network_connection=True."""
        telemetry = self.agent.simulate_reverse_shell()

        self.assertTrue(telemetry.network_connection)
        self.assertEqual(telemetry.event_type, "reverse_shell")
        self.assertEqual(telemetry.process_name, "nc.exe")

        event = self.agent.build_event(telemetry)
        self.assertTrue(event.endpoint.network_connection)
        self.assertEqual(event.domain, "ENDPOINT")

    def test_privilege_escalation_simulation_produces_elevated_status(self) -> None:
        """Requirement 5: Verify privilege escalation simulation produces elevated=True and SYSTEM level."""
        telemetry = self.agent.simulate_privilege_escalation()

        self.assertTrue(telemetry.elevated)
        self.assertEqual(telemetry.privilege_level, "SYSTEM")
        self.assertEqual(telemetry.event_type, "privilege_escalation")

        event = self.agent.build_event(telemetry)
        self.assertTrue(event.endpoint.elevated)
        self.assertEqual(event.endpoint.privilege_level, "SYSTEM")
        self.assertEqual(event.domain, "ENDPOINT")

    def test_unauthorized_transaction_simulation_produces_valid_event(self) -> None:
        """Requirement: Verify unauthorized transaction simulation produces valid telemetry and event."""
        telemetry = self.agent.simulate_unauthorized_transaction()
        self.assertEqual(telemetry.event_type, "unauthorized_transaction")
        self.assertTrue(telemetry.network_connection)
        self.assertEqual(telemetry.process_name, "browser_automation.exe")

        # Alias test
        alias_telem = self.agent.simulate_transaction_abuse()
        self.assertEqual(alias_telem.event_type, "unauthorized_transaction")

        event = self.agent.build_event(telemetry)
        self.assertIsInstance(event, ApiSecurityEvent)
        self.assertEqual(event.domain, "ENDPOINT")
        self.assertEqual(event.request.endpoint, "/api/transactions/transfer")
        self.assertEqual(event.resource.resource_type, "transaction")
        self.assertTrue(event.resource.is_sensitive)
        self.assertTrue(event.identity.is_authenticated)

    def test_fake_shopping_simulation_produces_valid_event(self) -> None:
        """Requirement: Verify fake shopping simulation produces valid telemetry and event."""
        telemetry = self.agent.simulate_fake_shopping()
        self.assertEqual(telemetry.event_type, "fake_shopping")
        self.assertTrue(telemetry.network_connection)
        self.assertIn("fake-shopping", telemetry.command_line)

        # Alias test
        alias_telem = self.agent.simulate_fraudulent_website()
        self.assertEqual(alias_telem.event_type, "fake_shopping")

        event = self.agent.build_event(telemetry)
        self.assertIsInstance(event, ApiSecurityEvent)
        self.assertEqual(event.domain, "ENDPOINT")
        self.assertEqual(event.request.endpoint, "/api/shopping/checkout")
        self.assertEqual(event.resource.resource_type, "shopping_session")
        self.assertTrue(event.resource.is_sensitive)

    def test_fake_bank_simulation_produces_valid_event(self) -> None:
        """Requirement: Verify fake bank / suspicious URL simulation produces valid telemetry and event."""
        telemetry = self.agent.simulate_fake_bank()
        self.assertEqual(telemetry.event_type, "fake_bank")
        self.assertTrue(telemetry.network_connection)
        self.assertEqual(telemetry.process_name, "chrome.exe")
        self.assertEqual(telemetry.parent_process, "outlook.exe")

        # Alias test
        alias_telem = self.agent.simulate_suspicious_url()
        self.assertEqual(alias_telem.event_type, "fake_bank")

        event = self.agent.build_event(telemetry)
        self.assertIsInstance(event, ApiSecurityEvent)
        self.assertEqual(event.domain, "ENDPOINT")
        self.assertEqual(event.request.endpoint, "/api/banking/login")
        self.assertEqual(event.resource.resource_type, "bank_account")
        self.assertTrue(event.resource.is_sensitive)

    def test_all_generated_events_pass_pydantic_validation(self) -> None:
        """Requirement 6: Verify all modes produce valid Pydantic ApiSecurityEvents."""
        scenarios = [
            self.agent.collect_telemetry(),
            self.agent.simulate_suspicious_process(),
            self.agent.simulate_keylogging(),
            self.agent.simulate_reverse_shell(),
            self.agent.simulate_privilege_escalation(),
            self.agent.simulate_unauthorized_transaction(),
            self.agent.simulate_fake_shopping(),
            self.agent.simulate_fake_bank(),
        ]

        for idx, telem in enumerate(scenarios):
            event = self.agent.build_event(telem, event_id=f"test-pydantic-validation-{idx}")
            self.assertIsInstance(event, ApiSecurityEvent)
            self.assertEqual(event.domain, "ENDPOINT")
            self.assertIsNotNone(event.network)
            self.assertIsNotNone(event.identity)
            self.assertIsNotNone(event.request)
            self.assertIsNotNone(event.response)

            # Test Pydantic serialization roundtrip
            dumped = event.model_dump(mode="json")
            self.assertEqual(dumped["domain"], "ENDPOINT")
            self.assertEqual(dumped["event_id"], f"test-pydantic-validation-{idx}")

    def test_agent_client_is_called_when_send_event_used(self) -> None:
        """Requirement 7: Verify send_event delegates strictly to AgentClient."""
        event = self.agent.build_event(self.agent.simulate_suspicious_process())
        mock_response = AgentResponse(success=True, status_code=200, data={"status": "success"})
        self.mock_client.send_event.return_value = mock_response

        resp = self.agent.send_event(event)

        self.mock_client.send_event.assert_called_once_with(event)
        self.assertTrue(resp.success)
        self.assertEqual(resp.status_code, 200)

    def test_cli_simulation_without_send_does_not_perform_http_requests(self) -> None:
        """Requirement 8: Verify simulation without --send does NOT call AgentClient.send_event."""
        with patch("agents.laptop_agent.AgentClient") as mock_client_cls:
            mock_inst = MagicMock(spec=AgentClient)
            mock_client_cls.return_value = mock_inst

            exit_code = main(["--mode", "simulate", "--scenario", "suspicious_process"])

            self.assertEqual(exit_code, 0)
            mock_inst.send_event.assert_not_called()

    def test_cli_simulation_with_send_calls_http_client(self) -> None:
        """Verify CLI with --send invokes AgentClient.send_event."""
        with patch("agents.laptop_agent.AgentClient") as mock_client_cls:
            mock_inst = MagicMock(spec=AgentClient)
            mock_inst.send_event.return_value = AgentResponse(
                success=True,
                status_code=200,
                data={"status": "success", "mitigation_action": "QUARANTINE"},
            )
            mock_client_cls.return_value = mock_inst

            exit_code = main(["--mode", "simulate", "--scenario", "suspicious_process", "--send"])

            self.assertEqual(exit_code, 0)
            mock_inst.send_event.assert_called_once()

    def test_cli_scenario_names_are_validated(self) -> None:
        """Requirement 9: Verify unrecognized scenario names or missing scenario flags raise error."""
        # 1. Invalid scenario name
        with self.assertRaises(SystemExit):
            parse_args(["--mode", "simulate", "--scenario", "non_existent_attack"])

        # 2. Missing scenario when in simulate mode
        with self.assertRaises(SystemExit):
            parse_args(["--mode", "simulate"])

        # 3. Valid scenarios parse cleanly
        for scen in [
            "suspicious_process",
            "keylogging",
            "reverse_shell",
            "privilege_escalation",
            "unauthorized_transaction",
            "transaction_abuse",
            "fake_shopping",
            "fraudulent_website",
            "fake_bank",
            "suspicious_url",
        ]:
            args = parse_args(["--mode", "simulate", "--scenario", scen])
            self.assertEqual(args.scenario, scen)

    def test_no_destructive_os_operations_occur(self) -> None:
        """Requirement 10: Verify no OS processes, sockets, or file changes are made by live collector."""
        with patch("subprocess.run") as mock_subproc, \
             patch("os.system") as mock_system, \
             patch("socket.socket") as mock_socket:

            telemetry = self.agent.collect_telemetry()

            # Ensure subprocess/system/socket connection was NEVER invoked
            mock_subproc.assert_not_called()
            mock_system.assert_not_called()
            mock_socket.assert_not_called()

            self.assertIsInstance(telemetry, EndpointInfo)


if __name__ == "__main__":
    unittest.main()
