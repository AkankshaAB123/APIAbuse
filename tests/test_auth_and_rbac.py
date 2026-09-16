"""Comprehensive tests for Server-Side Authentication & RBAC Device Authorization.

Covers:
1. Valid admin login -> 200 + JWT
2. Valid analyst login -> 200 + JWT
3. Valid device login -> 200 + JWT + device_ip
4. Invalid password -> 401
5. Missing/invalid JWT -> rejected (401)
6. Expired token -> rejected (401)
7. DEVICE GET /threats -> automatically scoped to its own destination_ip
8. DEVICE attempting ?device_ip=another-IP -> ignored; strictly scoped to its own IP
9. DEVICE GET /threats/{event_id} for own device -> 200 OK
10. DEVICE GET /threats/{event_id} for another device -> 404 (isolation, no leak)
11. ADMIN GET /threats -> returns global threats across all devices
12. ANALYST GET /threats -> returns global threats across all devices
13. DEVICE cannot access admin-only endpoint (/security-check, /statistics) -> 403
14. ADMIN/ANALYST can access admin-only endpoint -> 200
"""

from datetime import timedelta
import unittest
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.routes.auth import router as auth_router
from backend.routes.threats import router as threats_router
from backend.routes.security_check import router as security_check_router
from backend.services.auth_service import create_access_token


class TestAuthAndRBAC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = FastAPI()
        cls.app.include_router(auth_router)
        cls.app.include_router(threats_router)
        cls.app.include_router(security_check_router)
        cls.client = TestClient(cls.app)

    def _get_token(self, username, password):
        resp = self.client.post(
            "/auth/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(resp.status_code, 200)
        return resp.json()["access_token"]

    # 1. Valid admin login
    def test_1_valid_admin_login(self):
        resp = self.client.post(
            "/auth/login",
            json={"username": "admin", "password": "Admin@ThreatGuard2026!"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["user"]["role"], "ADMIN")
        self.assertEqual(data["user"]["username"], "admin")

    # 2. Valid analyst login
    def test_2_valid_analyst_login(self):
        resp = self.client.post(
            "/auth/login",
            json={"username": "analyst", "password": "Analyst@ThreatGuard2026!"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["role"], "ANALYST")

    # 3. Valid device login -> 200 + JWT + device_ip
    def test_3_valid_device_login(self):
        resp = self.client.post(
            "/auth/login",
            json={"username": "device", "password": "Device@ThreatGuard2026!"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["role"], "DEVICE")
        self.assertEqual(data["user"]["device_ip"], "10.165.192.186")

    # 4. Invalid password -> 401
    def test_4_invalid_password_returns_401(self):
        resp = self.client.post(
            "/auth/login",
            json={"username": "admin", "password": "WrongPassword!"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid username or password", resp.json()["detail"])

    # 5. Missing / invalid JWT -> 401
    def test_5_missing_or_invalid_jwt_rejected(self):
        # Missing
        resp = self.client.get("/threats")
        self.assertEqual(resp.status_code, 401)

        # Invalid
        resp_invalid = self.client.get(
            "/threats",
            headers={"Authorization": "Bearer not-a-valid-jwt-token"},
        )
        self.assertEqual(resp_invalid.status_code, 401)

    # 6. Expired token -> 401
    def test_6_expired_token_rejected(self):
        expired_token = create_access_token(
            data={"sub": "admin", "role": "ADMIN"},
            expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
        )
        resp = self.client.get(
            "/threats",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertIn("expired", resp.json()["detail"].lower())

    # 7. DEVICE GET /threats -> only its own destination_ip
    @patch("backend.routes.threats.events_collection")
    def test_7_device_get_threats_scopes_to_own_ip(self, mock_col):
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = [
            {
                "event_id": "evt-dev-1",
                "timestamp": "2026-09-16T08:00:00Z",
                "network": {"source_ip": "10.165.192.219", "destination_ip": "10.165.192.186"},
                "processing": {
                    "risk_assessment": {"threat_detected": True, "risk_score": 79.2, "risk_level": "HIGH"},
                    "mitigation_action": "RATE_LIMIT",
                },
            }
        ]
        mock_col.find.return_value = mock_cursor

        device_token = self._get_token("device", "Device@ThreatGuard2026!")
        resp = self.client.get(
            "/threats",
            headers={"Authorization": f"Bearer {device_token}"},
        )
        self.assertEqual(resp.status_code, 200)

        # Verify MongoDB was called strictly with destination_ip == 10.165.192.186
        mock_col.find.assert_called_once_with(
            {
                "processing.risk_assessment.threat_detected": True,
                "network.destination_ip": "10.165.192.186",
            }
        )

    # 8. DEVICE attempting ?device_ip=another-IP -> ignored; strictly scoped to its own IP
    @patch("backend.routes.threats.events_collection")
    def test_8_device_cannot_override_device_ip_param(self, mock_col):
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = []
        mock_col.find.return_value = mock_cursor

        device_token = self._get_token("device", "Device@ThreatGuard2026!")
        # Attempt to snoop on host 10.0.0.99
        resp = self.client.get(
            "/threats?device_ip=10.0.0.99",
            headers={"Authorization": f"Bearer {device_token}"},
        )
        self.assertEqual(resp.status_code, 200)

        # Server-side authorization MUST force destination_ip = 10.165.192.186
        mock_col.find.assert_called_once_with(
            {
                "processing.risk_assessment.threat_detected": True,
                "network.destination_ip": "10.165.192.186",
            }
        )

    # 9. DEVICE GET /threats/{event_id} for own device -> 200 OK
    @patch("backend.routes.threats.events_collection")
    def test_9_device_get_own_threat_by_id_succeeds(self, mock_col):
        mock_col.find_one.return_value = {
            "_id": "507f1f77bcf86cd799439011",
            "event_id": "evt-own-1",
            "network": {"destination_ip": "10.165.192.186"},
            "processing": {"mitigation_action": "RATE_LIMIT"},
        }
        device_token = self._get_token("device", "Device@ThreatGuard2026!")
        resp = self.client.get(
            "/threats/evt-own-1",
            headers={"Authorization": f"Bearer {device_token}"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["event_id"], "evt-own-1")

    # 10. DEVICE GET /threats/{event_id} for another device -> 404 (isolation, no leak)
    @patch("backend.routes.threats.events_collection")
    def test_10_device_get_other_threat_by_id_returns_404(self, mock_col):
        mock_col.find_one.return_value = {
            "_id": "507f1f77bcf86cd799439022",
            "event_id": "evt-other-2",
            "network": {"destination_ip": "192.168.1.50"},  # different device
            "processing": {"mitigation_action": "BLOCK"},
        }
        device_token = self._get_token("device", "Device@ThreatGuard2026!")
        resp = self.client.get(
            "/threats/evt-other-2",
            headers={"Authorization": f"Bearer {device_token}"},
        )
        self.assertEqual(resp.status_code, 404)

    # 11. ADMIN GET /threats -> returns global threats across all devices
    @patch("backend.routes.threats.events_collection")
    def test_11_admin_get_threats_global(self, mock_col):
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = [
            {
                "event_id": "evt-1",
                "network": {"destination_ip": "10.165.192.186"},
                "processing": {"risk_assessment": {"threat_detected": True}},
            },
            {
                "event_id": "evt-2",
                "network": {"destination_ip": "10.0.0.50"},
                "processing": {"risk_assessment": {"threat_detected": True}},
            },
        ]
        mock_col.find.return_value = mock_cursor

        admin_token = self._get_token("admin", "Admin@ThreatGuard2026!")
        resp = self.client.get(
            "/threats",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()), 2)
        mock_col.find.assert_called_once_with(
            {"processing.risk_assessment.threat_detected": True}
        )

    # 12. ANALYST GET /threats -> returns global threats across all devices
    @patch("backend.routes.threats.events_collection")
    def test_12_analyst_get_threats_global(self, mock_col):
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = []
        mock_col.find.return_value = mock_cursor

        analyst_token = self._get_token("analyst", "Analyst@ThreatGuard2026!")
        resp = self.client.get(
            "/threats",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        self.assertEqual(resp.status_code, 200)
        mock_col.find.assert_called_once_with(
            {"processing.risk_assessment.threat_detected": True}
        )

    # 13. DEVICE cannot access admin-only endpoint (/statistics) -> 403
    def test_13_device_cannot_access_admin_endpoint(self):
        device_token = self._get_token("device", "Device@ThreatGuard2026!")
        resp = self.client.get(
            "/statistics",
            headers={"Authorization": f"Bearer {device_token}"},
        )
        self.assertEqual(resp.status_code, 403)

    # 14. ADMIN/ANALYST can access admin-only endpoint (/statistics) -> 200
    @patch("backend.routes.threats.events_collection")
    def test_14_admin_can_access_statistics(self, mock_col):
        mock_col.count_documents.return_value = 10
        mock_col.aggregate.return_value = []

        admin_token = self._get_token("admin", "Admin@ThreatGuard2026!")
        resp = self.client.get(
            "/statistics",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("totalEvents", resp.json())



    # 15. Registration privilege escalation prevention: attempting to register ADMIN
    def test_15_registration_cannot_create_admin(self):
        import uuid
        uname = f"att_adm_{uuid.uuid4().hex[:6]}"
        resp = self.client.post(
            "/auth/register",
            json={"username": uname, "password": "SecurePassword123!", "role": "ADMIN"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        # Role must be strictly ANALYST, never ADMIN
        self.assertEqual(data["user"]["role"], "ANALYST")
        self.assertIsNone(data["user"]["device_ip"])

    # 16. Registration privilege escalation prevention: attempting to register DEVICE
    def test_16_registration_cannot_create_device(self):
        import uuid
        uname = f"att_dev_{uuid.uuid4().hex[:6]}"
        resp = self.client.post(
            "/auth/register",
            json={"username": uname, "password": "SecurePassword123!", "role": "DEVICE", "device_ip": "10.165.192.186"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        # Role must be strictly ANALYST, never DEVICE
        self.assertEqual(data["user"]["role"], "ANALYST")
        self.assertIsNone(data["user"]["device_ip"])

if __name__ == "__main__":
    unittest.main()
