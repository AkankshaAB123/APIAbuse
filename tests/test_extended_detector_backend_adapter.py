"""Backend-boundary coverage for the eight network and endpoint detectors."""

from datetime import datetime, timezone
import unittest

from api_detection.backend_adapter import adapt_backend_event, run_for_backend
from backend.schemas.api_security_event import (
    ApiSecurityEvent, EndpointInfo, IdentityInfo, NetworkInfo, RequestInfo,
    ResourceInfo, ResponseInfo,
)
from backend.schemas.detector_result import DetectorResult


def build_event(event_id, **overrides):
    network = {
        "source_ip": "192.0.2.10", "user_agent": "backend-adapter-test",
        "destination_ip": "198.51.100.10", "destination_port": 443,
        "protocol": "TCP", "bytes": 512, "packets": 4,
        "connection_status": "success",
    }
    network.update(overrides)
    return ApiSecurityEvent(
        event_id=event_id, timestamp=datetime(2026, 9, 1, tzinfo=timezone.utc),
        network=NetworkInfo(**network), identity=IdentityInfo(is_authenticated=True),
        request=RequestInfo(method="GET", endpoint="/api/demo"),
        response=ResponseInfo(status_code=200, latency_ms=10), resource=ResourceInfo(),
    )


def run(event, history=()):
    return {result["detector_id"]: result for result in run_for_backend(event, history)}


class BackendAdapterIntegrationTests(unittest.TestCase):
    def test_network_telemetry_reaches_all_network_detectors(self):
        current = build_event("network-current", connection_status="failed")
        adapted = adapt_backend_event(current)
        self.assertEqual(adapted.network.destination_port, 443)
        self.assertEqual(adapted.network.connection_status, "failed")

        distributed = run(current, [
            build_event(f"ddos-{port}", source_ip=f"192.0.2.{port}", destination_port=port)
            for port in range(1, 100)
        ])
        self.assertTrue(distributed["ddos"]["detected"])

        port_scan = run(current, [build_event(f"port-{port}", destination_port=port) for port in range(1, 100)])
        self.assertTrue(port_scan["port_scanning"]["detected"])

        repeated = run(current, [build_event(f"repeat-{number}", connection_status="failed") for number in range(99)])
        self.assertTrue(repeated["dos_flooding"]["detected"])
        self.assertTrue(repeated["network_brute_force"]["detected"])
        self.assertEqual({repeated[name]["domain"] for name in (
            "ddos", "dos_flooding", "port_scanning", "network_brute_force"
        )}, {"NETWORK"})

    def test_endpoint_telemetry_reaches_all_endpoint_detectors(self):
        event = build_event("endpoint-current")
        event.endpoint = EndpointInfo(
            event_type="process_network_activity", hostname="demo-host",
            process_name="powershell.exe", process_id=1234, parent_process="cmd.exe",
            command_line="powershell.exe -EncodedCommand SYNTHETIC_DEMO",
            privilege_level="administrator", keyboard_hook=True,
            network_connection=True, elevated=True,
        )
        self.assertIsNotNone(adapt_backend_event(event).endpoint)
        results = run(event)
        for detector_id in (
            "keylogging", "suspicious_process_execution", "reverse_shell", "privilege_escalation"
        ):
            self.assertTrue(results[detector_id]["detected"])
            self.assertEqual(DetectorResult.model_validate(results[detector_id]).domain, "ENDPOINT")

    def test_legacy_backend_event_still_returns_all_detectors(self):
        results = run(build_event("legacy-current"))
        self.assertEqual(len(results), 20)
        self.assertFalse(results["keylogging"]["detected"])
