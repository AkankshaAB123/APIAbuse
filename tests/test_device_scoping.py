"""Tests for device-scoped threats and gateway destination_ip resolution."""

import unittest
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.routes.threats import router as threats_router
from backend.services.auth_service import create_access_token
from gateway.proxy import extract_protected_host, GatewayConfig, create_gateway_app


class TestDeviceScoping(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = FastAPI()
        cls.app.include_router(threats_router)
        cls.client = TestClient(cls.app)
        cls.admin_token = create_access_token(data={"sub": "admin", "role": "ADMIN"})
        cls.device_token = create_access_token(data={"sub": "device", "role": "DEVICE", "device_ip": "10.165.192.186"})

    def test_extract_protected_host_from_url(self):
        self.assertEqual(extract_protected_host("http://10.165.192.186:8000"), "10.165.192.186")
        self.assertEqual(extract_protected_host("http://127.0.0.1:8000"), "127.0.0.1")
        self.assertEqual(extract_protected_host("http://protected-laptop:9090"), "protected-laptop")
        self.assertEqual(extract_protected_host("https://demo.internal.net"), "demo.internal.net")
        self.assertEqual(extract_protected_host(""), "127.0.0.1")

    def test_gateway_config_protected_host_resolution(self):
        cfg = GatewayConfig(target_base_url="http://10.165.192.186:8000")
        self.assertEqual(cfg.protected_host, "127.0.0.1")

        with patch.dict("os.environ", {"GATEWAY_PROTECTED_HOST": "192.168.1.50"}):
            app = create_gateway_app()
            self.assertEqual(app.state.config.protected_host, "192.168.1.50")

        with patch.dict(
            "os.environ",
            {"TARGET_BASE_URL": "http://10.165.192.186:8000"},
            clear=True,
        ):
            app = create_gateway_app()
            self.assertEqual(app.state.config.protected_host, "10.165.192.186")

    @patch("backend.routes.threats.events_collection")
    def test_get_threats_without_filter_returns_all(self, mock_collection):
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = [
            {
                "event_id": "evt-1",
                "timestamp": "2026-09-16T08:00:00Z",
                "network": {"source_ip": "10.165.192.219", "destination_ip": "10.165.192.186"},
                "processing": {
                    "risk_assessment": {"threat_detected": True, "risk_score": 80.0, "risk_level": "HIGH"},
                    "mitigation_action": "RATE_LIMIT",
                },
            },
            {
                "event_id": "evt-2",
                "timestamp": "2026-09-16T08:05:00Z",
                "network": {"source_ip": "10.0.0.5", "destination_ip": "10.0.0.99"},
                "processing": {
                    "risk_assessment": {"threat_detected": True, "risk_score": 90.0, "risk_level": "CRITICAL"},
                    "mitigation_action": "BLOCK",
                },
            },
        ]
        mock_collection.find.return_value = mock_cursor

        resp = self.client.get(
            "/threats",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 2)

        mock_collection.find.assert_called_once_with(
            {"processing.risk_assessment.threat_detected": True}
        )

    @patch("backend.routes.threats.events_collection")
    def test_get_threats_with_device_ip_filters_destination_ip(self, mock_collection):
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = [
            {
                "event_id": "evt-1",
                "timestamp": "2026-09-16T08:00:00Z",
                "network": {"source_ip": "10.165.192.219", "destination_ip": "10.165.192.186"},
                "processing": {
                    "risk_assessment": {"threat_detected": True, "risk_score": 80.0, "risk_level": "HIGH"},
                    "mitigation_action": "RATE_LIMIT",
                },
            }
        ]
        mock_collection.find.return_value = mock_cursor

        resp = self.client.get(
            "/threats",
            headers={"Authorization": f"Bearer {self.device_token}"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], "evt-1")

        mock_collection.find.assert_called_once_with(
            {
                "processing.risk_assessment.threat_detected": True,
                "network.destination_ip": "10.165.192.186",
            }
        )

    @patch("backend.routes.threats.events_collection")
    def test_get_threat_by_id_device_scoping(self, mock_collection):
        mock_doc = {
            "_id": "507f1f77bcf86cd799439011",
            "event_id": "evt-123",
            "network": {"destination_ip": "10.165.192.186"},
            "processing": {"mitigation_action": "RATE_LIMIT"},
        }
        mock_collection.find_one.return_value = mock_doc

        resp_ok = self.client.get(
            "/threats/evt-123",
            headers={"Authorization": f"Bearer {self.device_token}"},
        )
        self.assertEqual(resp_ok.status_code, 200)

        # Mismatched doc destination_ip
        mock_other = {
            "_id": "507f1f77bcf86cd799439012",
            "event_id": "evt-other",
            "network": {"destination_ip": "192.168.1.99"},
            "processing": {"mitigation_action": "BLOCK"},
        }
        mock_collection.find_one.return_value = mock_other
        resp_blocked = self.client.get(
            "/threats/evt-other",
            headers={"Authorization": f"Bearer {self.device_token}"},
        )
        self.assertEqual(resp_blocked.status_code, 404)

        # Admin call succeeds
        resp_admin = self.client.get(
            "/threats/evt-other",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(resp_admin.status_code, 200)


if __name__ == "__main__":
    unittest.main()
