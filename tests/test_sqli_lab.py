"""Tests for ThreatGuard Automated Controlled SQL Injection Lab & Attack Simulator.

Verifies:
1. Benign request is allowed (HTTP 200).
2. Simulator produces a real HTTP request against /lab/sqli.
3. SQLi detector identifies the malicious request.
4. EventProcessor is exercised.
5. RiskEngine is exercised (Risk Score: 80.4, Level: HIGH).
6. MitigationService is exercised (Action: RATE_LIMIT / BLOCK).
7. Malicious request receives HTTP 403 Forbidden with Active Defense blocked page.
8. Automated simulation endpoint (/lab/sqli/simulate and /lab/attacks/sql-injection)
   dispatches the attack and reports the live ThreatGuard interception.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.routes.sqli_lab import AUTOMATED_SQLI_SIMULATION_PAYLOAD


class AutomatedSqliSimulatorTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_1_get_simulator_page_renders_html(self):
        """GET /lab/sqli should display the automated SQLi simulator console."""
        response = self.client.get("/lab/sqli")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("content-type", ""))
        self.assertIn("Automated SQLi Attack Simulator", response.text)
        self.assertIn("Run SQL Injection Simulation", response.text)
        self.assertIn("Run Baseline Benign Request", response.text)

    def test_2_benign_request_allowed_with_200(self):
        """Benign request to /lab/sqli is allowed with HTTP 200 and catalog results."""
        response = self.client.post(
            "/lab/sqli",
            json={"query": "laptop"},
            headers={"Accept": "application/json", "X-Forwarded-For": "192.168.1.50"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "allowed")
        self.assertEqual(data["mitigation_action"], "ALLOW")
        self.assertEqual(data["risk_level"], "LOW")
        self.assertEqual(data["risk_score"], 0.0)
        self.assertEqual(response.headers.get("X-ThreatGuard-Action"), "ALLOW")

    def test_3_simulator_produces_real_http_request_and_receives_403(self):
        """Simulator dispatches real HTTP request to /lab/sqli; ThreatGuard intercepts with HTTP 403."""
        # This simulates the real HTTP request that the simulator sends to /lab/sqli
        response = self.client.post(
            "/lab/sqli",
            json={"query": AUTOMATED_SQLI_SIMULATION_PAYLOAD},
            headers={"Accept": "application/json", "X-Forwarded-For": "192.168.1.100"},
        )
        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertEqual(data["status"], "blocked")
        self.assertEqual(data["error"], "access_forbidden")
        self.assertEqual(data["attack_type"], "SQL_INJECTION")
        self.assertTrue(data["incident_id"].startswith("evt-sqli-"))
        self.assertIn(response.headers.get("X-ThreatGuard-Action"), ("RATE_LIMIT", "BLOCK"))

    def test_4_sqli_detector_identifies_malicious_request(self):
        """Verify the existing SQLi detector identified the injection pattern."""
        response = self.client.post(
            "/lab/sqli",
            json={"query": "1' UNION SELECT username, password FROM users; --"},
            headers={"Accept": "application/json", "X-Forwarded-For": "192.168.1.100"},
        )
        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertEqual(data["attack_type"], "SQL_INJECTION")
        self.assertIn("Suspicious SQL injection pattern", data["details"])

    def test_5_event_processor_and_risk_engine_exercised(self):
        """Verify EventProcessor and RiskEngine calculated dynamic risk score."""
        response = self.client.post(
            "/lab/sqli",
            json={"query": AUTOMATED_SQLI_SIMULATION_PAYLOAD},
            headers={"Accept": "application/json", "X-Forwarded-For": "192.168.1.100"},
        )
        self.assertEqual(response.status_code, 403)
        data = response.json()
        # RiskEngine score for HIGH severity (70) and 0.96 confidence = 80.4
        self.assertEqual(data["risk_level"], "HIGH")
        self.assertAlmostEqual(data["risk_score"], 80.4, places=1)
        self.assertEqual(response.headers.get("X-ThreatGuard-Risk-Score"), "80.4")

    def test_6_mitigation_service_enforces_active_defense_block(self):
        """Verify MitigationService applied non-ALLOW active mitigation action."""
        response = self.client.post(
            "/lab/sqli",
            json={"query": AUTOMATED_SQLI_SIMULATION_PAYLOAD},
            headers={"Accept": "application/json", "X-Forwarded-For": "192.168.1.100"},
        )
        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertNotEqual(data["enforcement"], "ALLOW")
        self.assertIn(data["enforcement"], ("RATE_LIMIT", "BLOCK"))
        self.assertEqual(response.headers.get("X-ThreatGuard-Action"), data["enforcement"])

    def test_7_html_blocked_page_renders_active_defense(self):
        """Browser form submission receives styled HTTP 403 active defense HTML screen."""
        response = self.client.post(
            "/lab/sqli",
            data={"query": AUTOMATED_SQLI_SIMULATION_PAYLOAD},
            headers={"X-Forwarded-For": "192.168.1.100"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("text/html", response.headers.get("content-type", ""))
        self.assertIn("Access Blocked (HTTP 403)", response.text)
        self.assertIn("ThreatGuard Active Defense", response.text)
        self.assertIn("SQL_INJECTION", response.text)
        self.assertIn("Incident ID:", response.text)

    def test_8_automated_simulation_endpoint_executes_attack(self):
        """Automated simulation endpoint /lab/sqli/simulate generates attack and reports defense."""
        response = self.client.post(
            "/lab/sqli/simulate",
            headers={"X-Forwarded-For": "192.168.1.200"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["simulation_type"], "SQL_INJECTION")
        self.assertEqual(data["target_endpoint"], "/lab/sqli")
        self.assertEqual(data["generated_payload"], AUTOMATED_SQLI_SIMULATION_PAYLOAD)

        interception = data["threatguard_interception"]
        self.assertTrue(interception["threat_detected"])
        self.assertEqual(interception["attack_type"], "SQL_INJECTION")
        self.assertEqual(interception["enforcement_http_status"], 403)
        self.assertAlmostEqual(interception["risk_score"], 80.4, places=1)
        self.assertEqual(interception["risk_level"], "HIGH")

    def test_9_attacker_console_compatible_endpoint(self):
        """Compatible endpoint /lab/attacks/sql-injection operates cleanly."""
        response = self.client.post(
            "/lab/attacks/sql-injection",
            headers={"X-Forwarded-For": "192.168.1.201"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["threatguard_interception"]["enforcement_http_status"], 403)


if __name__ == "__main__":
    unittest.main()
