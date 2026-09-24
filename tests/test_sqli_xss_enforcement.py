"""Automated Tests for ThreatGuard Gateway Real Enforcement: SQLi and XSS.

Verifies:
1. Malicious SQLi request through Gateway :8080:
   - Evaluated by real backend /events and api_detection/detectors/sql_injection.py
   - Mitigation (RATE_LIMIT / BLOCK) enforced by Gateway
   - Response rejected (HTTP 429 / 403)
   - Protected /demo-search invocation count strictly does NOT increase
2. Benign SQL search request through Gateway:
   - Evaluated by real backend /events -> ALLOW
   - Gateway forwards to /demo-search
   - Protected target is reached (HTTP 200) and invocation count increases
3. Malicious XSS request through Gateway :8080:
   - Evaluated by real backend /events and api_detection/detectors/xss.py
   - Mitigation (RATE_LIMIT / BLOCK) enforced by Gateway
   - Response rejected (HTTP 429 / 403)
   - Protected /demo-comment invocation count strictly does NOT increase
4. Benign comment request through Gateway:
   - Evaluated by real backend /events -> ALLOW
   - Gateway forwards to /demo-comment
   - Protected target is reached (HTTP 200) and invocation count increases
5. Subsequent requests from blocked/rate-limited IP are rejected at gateway level
"""

import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.main import app as backend_app
from backend.routes.demo_target import (
    get_demo_target_invocation_count,
    get_demo_search_invocation_count,
    get_demo_comment_invocation_count,
    reset_demo_target_invocation_count,
)
from gateway.enforcement_table import EnforcementTable
from gateway.proxy import create_gateway_app


class SqliXssEnforcementGatewayTests(unittest.TestCase):

    def setUp(self):
        reset_demo_target_invocation_count()
        self.table = EnforcementTable(
            default_ttls={
                "BLOCK": 5.0,
                "RATE_LIMIT": 5.0,
            },
            rate_limit_max_requests=0,  # immediate rejection when under RATE_LIMIT
            rate_limit_window_seconds=10.0,
        )
        self.backend_client = TestClient(backend_app)

        # Wire gateway event submitter directly to real backend /events route
        def submit_to_backend(event_dict):
            resp = self.backend_client.post("/events", json=event_dict)
            return resp.json()

        # Wire gateway forwarder directly to real backend application
        def forward_to_backend(method, path, headers, body):
            resp = self.backend_client.request(method, path, headers=headers, content=body)
            return resp.status_code, dict(resp.headers), resp.content

        self.gw_app = create_gateway_app(
            enforcement_table=self.table,
            event_submitter=submit_to_backend,
            target_forwarder=forward_to_backend,
        )
        self.gw_client = TestClient(self.gw_app)

    def tearDown(self):
        self.table.reset_all()
        reset_demo_target_invocation_count()

    @patch("backend.services.event_processor.analyze_threat")
    def test_1_sqli_attack_blocked_target_not_reached(self, mock_rag):
        """SQLi attack through gateway is detected, mitigated, and never reaches target."""
        mock_rag.return_value = {"summary": "SQL injection detected"}

        attacker_ip = "198.51.100.10"
        sqli_payload = "' OR 1=1 --"

        count_before_total = get_demo_target_invocation_count()
        count_before_search = get_demo_search_invocation_count()

        # Send malicious request through gateway
        resp = self.gw_client.get(
            f"/demo-search?query={sqli_payload}",
            headers={"X-Forwarded-For": attacker_ip},
        )

        # Gateway must enforce mitigation (RATE_LIMIT -> 429 or BLOCK -> 403)
        self.assertIn(resp.status_code, (403, 429))
        self.assertIn(resp.headers.get("X-ThreatGuard-Action"), ("RATE_LIMIT", "BLOCK"))

        # Target invocation counters must strictly NOT increase
        self.assertEqual(get_demo_target_invocation_count(), count_before_total)
        self.assertEqual(get_demo_search_invocation_count(), count_before_search)

        # Verify enforcement table state was recorded for attacker IP
        state = self.table.get_state(attacker_ip)
        self.assertIsNotNone(state)
        self.assertIn(state.action, ("RATE_LIMIT", "BLOCK"))

    @patch("backend.services.event_processor.analyze_threat")
    def test_2_benign_sql_search_allowed_target_reached(self, mock_rag):
        """Benign search request through gateway is allowed and reaches target."""
        clean_ip = "198.51.100.20"
        benign_query = "Laptop"

        count_before_total = get_demo_target_invocation_count()
        count_before_search = get_demo_search_invocation_count()

        resp = self.gw_client.get(
            f"/demo-search?query={benign_query}",
            headers={"X-Forwarded-For": clean_ip},
        )

        # Must succeed and reach target
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["query"], benign_query)
        self.assertEqual(resp.headers.get("X-ThreatGuard-Action"), "ALLOW")

        # Target invocation counters must increase by exactly 1
        self.assertEqual(get_demo_target_invocation_count(), count_before_total + 1)
        self.assertEqual(get_demo_search_invocation_count(), count_before_search + 1)

    @patch("backend.services.event_processor.analyze_threat")
    def test_3_xss_attack_blocked_target_not_reached(self, mock_rag):
        """XSS attack through gateway is detected, mitigated, and never reaches target."""
        mock_rag.return_value = {"summary": "XSS script tag detected"}

        attacker_ip = "198.51.100.30"
        xss_payload = "<script>alert(1)</script>"

        count_before_total = get_demo_target_invocation_count()
        count_before_comment = get_demo_comment_invocation_count()

        # Send malicious request through gateway
        resp = self.gw_client.get(
            f"/demo-comment?q={xss_payload}",
            headers={"X-Forwarded-For": attacker_ip},
        )

        # Gateway must enforce mitigation (RATE_LIMIT -> 429 or BLOCK -> 403)
        self.assertIn(resp.status_code, (403, 429))
        self.assertIn(resp.headers.get("X-ThreatGuard-Action"), ("RATE_LIMIT", "BLOCK"))

        # Target invocation counters must strictly NOT increase
        self.assertEqual(get_demo_target_invocation_count(), count_before_total)
        self.assertEqual(get_demo_comment_invocation_count(), count_before_comment)

        # Verify enforcement table state was recorded for attacker IP
        state = self.table.get_state(attacker_ip)
        self.assertIsNotNone(state)
        self.assertIn(state.action, ("RATE_LIMIT", "BLOCK"))

    @patch("backend.services.event_processor.analyze_threat")
    def test_4_benign_comment_allowed_target_reached(self, mock_rag):
        """Benign comment request through gateway is allowed and reaches target."""
        clean_ip = "198.51.100.40"
        benign_comment = "Great product review!"

        count_before_total = get_demo_target_invocation_count()
        count_before_comment = get_demo_comment_invocation_count()

        resp = self.gw_client.get(
            f"/demo-comment?q={benign_comment}",
            headers={"X-Forwarded-For": clean_ip},
        )

        # Must succeed and reach target
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["input"], benign_comment)
        self.assertEqual(resp.headers.get("X-ThreatGuard-Action"), "ALLOW")

        # Target invocation counters must increase by exactly 1
        self.assertEqual(get_demo_target_invocation_count(), count_before_total + 1)
        self.assertEqual(get_demo_comment_invocation_count(), count_before_comment + 1)

    @patch("backend.services.event_processor.analyze_threat")
    def test_5_active_enforcement_prevents_subsequent_requests(self, mock_rag):
        """Once mitigated, subsequent requests from the same IP are blocked without reaching target."""
        mock_rag.return_value = {"summary": "SQL injection detected"}

        attacker_ip = "198.51.100.50"
        sqli_payload = "' OR 1=1 --"

        count_before = get_demo_target_invocation_count()

        # Request 1: Triggers SQLi detection -> mitigated
        r1 = self.gw_client.get(
            f"/demo-search?query={sqli_payload}",
            headers={"X-Forwarded-For": attacker_ip},
        )
        self.assertIn(r1.status_code, (403, 429))
        self.assertEqual(get_demo_target_invocation_count(), count_before)

        # Request 2: Even a benign search from the same IP is blocked by active enforcement
        r2 = self.gw_client.get(
            "/demo-search?query=harmless",
            headers={"X-Forwarded-For": attacker_ip},
        )
        self.assertIn(r2.status_code, (403, 429))
        self.assertEqual(get_demo_target_invocation_count(), count_before)

        # Request 3: Different clean IP is NOT blocked
        clean_ip = "198.51.100.60"
        r3 = self.gw_client.get(
            "/demo-search?query=harmless",
            headers={"X-Forwarded-For": clean_ip},
        )
        self.assertEqual(r3.status_code, 200)
        self.assertEqual(get_demo_target_invocation_count(), count_before + 1)


if __name__ == "__main__":
    unittest.main()
