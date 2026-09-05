from unittest import TestCase

from api_detection.contracts import AttackType, DetectorDomain
from api_detection.detectors import (
    detect_ddos,
    detect_dos_flooding,
    detect_keylogging,
    detect_network_brute_force,
    detect_port_scanning,
    detect_privilege_escalation,
    detect_reverse_shell,
    detect_suspicious_process_execution,
)
from api_detection.simulator import (
    ddos_event,
    dos_flooding_event,
    endpoint_privilege_escalation_event,
    keylogging_event,
    network_brute_force_event,
    port_scanning_event,
    reverse_shell_event,
    suspicious_process_execution_event,
)


class SimulatorScenarioTests(TestCase):
    def test_ddos_scenario_detects_with_distributed_history(self):
        event = ddos_event()
        recent_events = [
            ddos_event(
                event_id=f"evt-ddos-{index}",
                source_ip=f"192.0.2.{index}",
            )
            for index in range(1, 100)
        ]

        result = detect_ddos(event, recent_events)

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.DDOS)
        self.assertEqual(result.domain, DetectorDomain.NETWORK)

    def test_dos_flooding_scenario_detects_with_high_volume_history(self):
        event = dos_flooding_event()
        recent_events = [
            dos_flooding_event(
                event_id=f"evt-dos-{index}",
            )
            for index in range(1, 100)
        ]

        result = detect_dos_flooding(event, recent_events)

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.DOS_FLOODING)
        self.assertEqual(result.domain, DetectorDomain.NETWORK)

    def test_port_scanning_scenario_detects_with_many_ports(self):
        event = port_scanning_event(destination_port=1000)
        recent_events = [
            port_scanning_event(
                event_id=f"evt-port-scan-{index}",
                destination_port=index,
            )
            for index in range(1, 100)
        ]

        result = detect_port_scanning(event, recent_events)

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.PORT_SCANNING)
        self.assertEqual(result.domain, DetectorDomain.NETWORK)

    def test_network_brute_force_scenario_detects_with_failed_history(self):
        event = network_brute_force_event()
        recent_events = [
            network_brute_force_event(
                event_id=f"evt-network-brute-force-{index}",
            )
            for index in range(1, 10)
        ]

        result = detect_network_brute_force(event, recent_events)

        self.assertTrue(result.detected)
        self.assertEqual(
            result.attack_type,
            AttackType.NETWORK_BRUTE_FORCE,
        )
        self.assertEqual(result.domain, DetectorDomain.NETWORK)

    def test_keylogging_scenario_detects_keyboard_hook(self):
        result = detect_keylogging(keylogging_event())

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.KEYLOGGING)
        self.assertEqual(result.domain, DetectorDomain.ENDPOINT)

    def test_suspicious_process_scenario_detects(self):
        result = detect_suspicious_process_execution(
            suspicious_process_execution_event()
        )

        self.assertTrue(result.detected)
        self.assertEqual(
            result.attack_type,
            AttackType.SUSPICIOUS_PROCESS_EXECUTION,
        )
        self.assertEqual(result.domain, DetectorDomain.ENDPOINT)

    def test_reverse_shell_scenario_detects(self):
        result = detect_reverse_shell(reverse_shell_event())

        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, AttackType.REVERSE_SHELL)
        self.assertEqual(result.domain, DetectorDomain.ENDPOINT)

    def test_endpoint_privilege_escalation_scenario_detects(self):
        result = detect_privilege_escalation(
            endpoint_privilege_escalation_event()
        )

        self.assertTrue(result.detected)
        self.assertEqual(
            result.attack_type,
            AttackType.PRIVILEGE_ESCALATION,
        )
        self.assertEqual(result.domain, DetectorDomain.ENDPOINT)