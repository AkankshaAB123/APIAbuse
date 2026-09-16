"""Tests for shared AgentClient and AgentResponse."""

import copy
from datetime import datetime, timezone
import io
import json
import os
import socket
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from agents.agent_client import AgentClient, AgentResponse
from backend.schemas.api_security_event import (
    ApiSecurityEvent,
    EndpointInfo,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResponseInfo,
)


class DummyHTTPResponse:
    """Mock HTTP response object for urllib.request.urlopen context manager."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status
        self.code = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class TestAgentClient(unittest.TestCase):
    """Unit tests verifying AgentClient transport and error handling."""

    def setUp(self) -> None:
        self.client = AgentClient(endpoint_url="http://localhost:8000/events", timeout=5.0)

    def test_pydantic_event_serialization(self) -> None:
        """Verify Pydantic ApiSecurityEvent is serialized cleanly with all fields preserved."""
        event = ApiSecurityEvent(
            event_id="test-pydantic-001",
            timestamp=datetime(2026, 9, 11, 12, 0, 0, tzinfo=timezone.utc),
            network=NetworkInfo(
                source_ip="192.168.1.105",
                user_agent="TestAgent/1.0",
                destination_ip="10.0.0.1",
                source_port=51234,
                destination_port=8000,
                protocol="TCP",
                bytes=2048,
                packets=15,
                connection_status="ESTABLISHED",
            ),
            endpoint=EndpointInfo(
                event_type="process_creation",
                hostname="SEC-WORKSTATION-01",
                username="analyst",
                process_name="powershell.exe",
                process_id=4096,
                command_line="powershell.exe -enc test",
                privilege_level="USER",
            ),
            identity=IdentityInfo(
                user_id="usr-1",
                session_id="sess-1",
                roles=["analyst"],
                is_authenticated=True,
            ),
            request=RequestInfo(
                method="POST",
                endpoint="/api/telemetry",
                query_params={"dry_run": "true"},
            ),
            response=ResponseInfo(
                status_code=200,
                latency_ms=12.5,
            ),
        )

        mock_resp = DummyHTTPResponse(
            body=json.dumps({"status": "success", "event_id": "test-pydantic-001"}).encode("utf-8"),
            status=200,
        )

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            resp = self.client.send_event(event)

            self.assertTrue(resp.success)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.data.get("event_id"), "test-pydantic-001")
            self.assertIsNone(resp.error)

            # Verify underlying Request object passed to urlopen
            self.assertEqual(mock_urlopen.call_count, 1)
            req = mock_urlopen.call_args[0][0]
            self.assertEqual(req.get_method(), "POST")
            self.assertEqual(req.full_url, "http://localhost:8000/events")
            self.assertEqual(req.get_header("Content-type"), "application/json")

            sent_json = json.loads(req.data.decode("utf-8"))
            self.assertEqual(sent_json["event_id"], "test-pydantic-001")
            self.assertEqual(sent_json["network"]["source_ip"], "192.168.1.105")
            self.assertEqual(sent_json["endpoint"]["process_name"], "powershell.exe")
            self.assertEqual(sent_json["endpoint"]["process_id"], 4096)
            self.assertEqual(sent_json["request"]["method"], "POST")
            self.assertEqual(sent_json["response"]["status_code"], 200)

    def test_dictionary_payload_sending(self) -> None:
        """Verify dict-based events are serialized and sent without errors."""
        payload_dict = {
            "event_id": "test-dict-002",
            "timestamp": datetime(2026, 9, 11, 12, 5, 0, tzinfo=timezone.utc),
            "network": {
                "source_ip": "10.10.10.50",
                "destination_ip": "10.10.10.1",
            },
            "request": {
                "method": "GET",
                "endpoint": "/health",
            },
            "response": {
                "status_code": 200,
            },
        }

        mock_resp = DummyHTTPResponse(
            body=json.dumps({"status": "success", "event_id": "test-dict-002"}).encode("utf-8"),
            status=200,
        )

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            resp = self.client.send_event(payload_dict)

            self.assertTrue(resp.success)
            self.assertEqual(resp.status_code, 200)

            req = mock_urlopen.call_args[0][0]
            sent_data = json.loads(req.data.decode("utf-8"))
            self.assertEqual(sent_data["event_id"], "test-dict-002")
            self.assertEqual(sent_data["network"]["source_ip"], "10.10.10.50")
            # Datetime must be serialized to ISO string
            self.assertIn("2026-09-11T12:05:00", sent_data["timestamp"])

    def test_configurable_backend_url(self) -> None:
        """Verify endpoint URL can be configured via constructor or environment variable."""
        # 1. Default URL
        default_client = AgentClient()
        self.assertEqual(default_client.endpoint_url, "http://localhost:8000/events")

        # 2. Constructor argument with full endpoint
        custom_client = AgentClient(endpoint_url="http://cloud-host:9000/events")
        self.assertEqual(custom_client.endpoint_url, "http://cloud-host:9000/events")

        # 3. Constructor base_url without trailing /events
        base_client = AgentClient(base_url="http://cloud-host:9000")
        self.assertEqual(base_client.endpoint_url, "http://cloud-host:9000/events")

        # 4. Constructor base_url with trailing slash
        trailing_slash_client = AgentClient(endpoint_url="http://cloud-host:9000/")
        self.assertEqual(trailing_slash_client.endpoint_url, "http://cloud-host:9000/events")

        # 5. Environment variable API_BACKEND_URL
        with patch.dict(os.environ, {"API_BACKEND_URL": "http://env-server:7000"}):
            env_client = AgentClient()
            self.assertEqual(env_client.endpoint_url, "http://env-server:7000/events")

        # 6. Environment variable with full endpoint
        with patch.dict(os.environ, {"API_BACKEND_URL": "http://env-server:7000/events"}):
            env_client_full = AgentClient()
            self.assertEqual(env_client_full.endpoint_url, "http://env-server:7000/events")

    def test_successful_http_response_handling(self) -> None:
        """Verify successful response structure and property access."""
        backend_response_data = {
            "status": "success",
            "event_id": "test-resp-001",
            "mitigation_action": "QUARANTINE",
            "risk_assessment": {"score": 85.0, "severity": "HIGH"},
        }

        mock_resp = DummyHTTPResponse(
            body=json.dumps(backend_response_data).encode("utf-8"),
            status=200,
        )

        with patch("urllib.request.urlopen", return_value=mock_resp):
            resp = self.client.send_event({"event_id": "test-resp-001"})

            self.assertTrue(resp.success)
            self.assertTrue(bool(resp))
            self.assertEqual(resp.status_code, 200)
            self.assertIsNone(resp.error)
            self.assertEqual(resp.data, backend_response_data)

            # Test dict-like access
            self.assertEqual(resp["mitigation_action"], "QUARANTINE")
            self.assertEqual(resp.get("mitigation_action"), "QUARANTINE")
            self.assertEqual(resp["status_code"], 200)
            self.assertTrue(resp["success"])

            # Test to_dict()
            as_dict = resp.to_dict()
            self.assertTrue(as_dict["success"])
            self.assertEqual(as_dict["status_code"], 200)
            self.assertEqual(as_dict["data"]["mitigation_action"], "QUARANTINE")

    def test_http_error_handling_4xx_and_5xx(self) -> None:
        """Verify HTTP 4xx and 5xx errors are cleanly caught without process crash."""
        # 1. Test HTTP 422 Unprocessable Entity
        http_422 = urllib.error.HTTPError(
            url="http://localhost:8000/events",
            code=422,
            msg="Unprocessable Entity",
            hdrs={},
            fp=io.BytesIO(b'{"detail": [{"loc": ["body", "network"], "msg": "field required"}]}'),
        )
        with patch("urllib.request.urlopen", side_effect=http_422):
            resp = self.client.send_event({"invalid": "payload"})

            self.assertFalse(resp.success)
            self.assertEqual(resp.status_code, 422)
            self.assertIn("422", resp.error)
            self.assertIsNotNone(resp.data)
            self.assertIn("detail", resp.data)

        # 2. Test HTTP 500 Internal Server Error
        http_500 = urllib.error.HTTPError(
            url="http://localhost:8000/events",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=io.BytesIO(b'{"detail": "Event processing failed: database offline"}'),
        )
        with patch("urllib.request.urlopen", side_effect=http_500):
            resp = self.client.send_event({"event_id": "test-500"})

            self.assertFalse(resp.success)
            self.assertEqual(resp.status_code, 500)
            self.assertIn("500", resp.error)
            self.assertIn("database offline", resp.data.get("detail", ""))

    def test_connection_transport_failure_handling(self) -> None:
        """Verify connection refused and unreachable network errors are handled cleanly."""
        url_err = urllib.error.URLError(ConnectionRefusedError(10061, "Connection refused"))

        with patch("urllib.request.urlopen", side_effect=url_err):
            resp = self.client.send_event({"event_id": "test-conn-refused"})

            self.assertFalse(resp.success)
            self.assertIsNone(resp.status_code)
            self.assertIsNotNone(resp.error)
            self.assertIn("Connection refused", resp.error)

    def test_timeout_error_handling(self) -> None:
        """Verify socket and URL timeouts are caught and structured without crashing."""
        # 1. Direct socket.timeout
        with patch("urllib.request.urlopen", side_effect=socket.timeout("Operation timed out")):
            resp = self.client.send_event({"event_id": "test-timeout-1"})

            self.assertFalse(resp.success)
            self.assertIsNone(resp.status_code)
            self.assertIn("timed out", resp.error.lower())

        # 2. Timeout wrapped in URLError
        wrapped_timeout = urllib.error.URLError(socket.timeout("Operation timed out"))
        with patch("urllib.request.urlopen", side_effect=wrapped_timeout):
            resp = self.client.send_event({"event_id": "test-timeout-2"})

            self.assertFalse(resp.success)
            self.assertIsNone(resp.status_code)
            self.assertIn("timed out", resp.error.lower())

    def test_malformed_response_handling(self) -> None:
        """Verify that a 200 response with invalid JSON is handled cleanly."""
        mock_resp = DummyHTTPResponse(
            body=b"<html><body>502 Bad Gateway from reverse proxy</body></html>",
            status=200,
        )

        with patch("urllib.request.urlopen", return_value=mock_resp):
            resp = self.client.send_event({"event_id": "test-bad-json"})

            self.assertFalse(resp.success)
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Malformed JSON", resp.error)
            self.assertIn("502 Bad Gateway", resp.raw_response)

    def test_payload_not_unexpectedly_altered(self) -> None:
        """Verify that the client never mutates or alters the input event payload."""
        original_dict = {
            "event_id": "unaltered-001",
            "timestamp": "2026-09-11T10:00:00Z",
            "network": {
                "source_ip": "192.168.1.1",
                "ports": [80, 443, 8080],
            },
            "tags": ["critical", "production"],
        }
        deep_copied_dict = copy.deepcopy(original_dict)

        mock_resp = DummyHTTPResponse(
            body=b'{"status": "success"}',
            status=200,
        )

        with patch("urllib.request.urlopen", return_value=mock_resp):
            self.client.send_event(original_dict)

            # Assert original dictionary is strictly identical to the pre-send deep copy
            self.assertEqual(original_dict, deep_copied_dict)

    def test_unsupported_event_type_handling(self) -> None:
        """Verify passing an unsupported type returns a structured error without crashing."""
        resp = self.client.send_event(12345)

        self.assertFalse(resp.success)
        self.assertIsNone(resp.status_code)
        self.assertIn("serialization failed", resp.error.lower())


if __name__ == "__main__":
    unittest.main()
