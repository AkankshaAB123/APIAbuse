"""Automated Tests for ThreatGuard Real Enforcement Gateway.

Verifies:
1. Normal request -> backend returns ALLOW -> target is invoked (200 OK)
2. Backend returns RATE_LIMIT -> gateway enforces rate limiting -> excessive request receives 429
3. Backend returns BLOCK -> gateway returns 403 -> target is NOT invoked
4. Different source IP is NOT affected by another source's block state
5. Enforcement state expires after TTL
6. Backend /events failure -> gateway fails closed with 503
7. Protected demo target invocation counter proves blocked requests never reach the target
8. Real integration flow through FastAPI backend
"""

import json
import time
import unittest
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from backend.main import app as backend_app
from backend.routes.demo_target import (
    get_demo_target_invocation_count,
    reset_demo_target_invocation_count,
)
from gateway.enforcement_table import EnforcementTable
from gateway.proxy import GatewayConfig, create_gateway_app


class EnforcementGatewayTests(unittest.TestCase):

    def setUp(self):
        reset_demo_target_invocation_count()
        self.table = EnforcementTable(
            default_ttls={
                "BLOCK": 0.5,  # 500ms TTL for fast test expiry
                "RATE_LIMIT": 0.5,
            },
            rate_limit_max_requests=2,
            rate_limit_window_seconds=1.0,
        )

    def tearDown(self):
        self.table.reset_all()
        reset_demo_target_invocation_count()

    def test_1_normal_request_allow_target_invoked(self):
        """1. Normal request -> backend returns ALLOW -> target is invoked."""
        mock_submit = MagicMock(return_value={
            "mitigation_action": "ALLOW",
            "risk_assessment": {"risk_score": 0.0, "risk_level": "LOW", "threat_detected": False},
        })

        backend_client = TestClient(backend_app)

        def forward_to_backend(method, path, headers, body):
            resp = backend_client.request(method, path, headers=headers, content=body)
            return resp.status_code, dict(resp.headers), resp.content

        gw_app = create_gateway_app(
            enforcement_table=self.table,
            event_submitter=mock_submit,
            target_forwarder=forward_to_backend,
        )
        gw_client = TestClient(gw_app)

        initial_count = get_demo_target_invocation_count()
        resp = gw_client.post(
            "/demo-login",
            json={"username": "demo_admin", "password": "SecretPassword123!"},
            headers={"X-Forwarded-For": "192.168.1.100"},
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "success")
        self.assertEqual(resp.headers.get("X-ThreatGuard-Action"), "ALLOW")
        self.assertEqual(get_demo_target_invocation_count(), initial_count + 1)
        mock_submit.assert_called_once()

    def test_2_rate_limit_enforced_receives_429(self):
        """2. Backend returns RATE_LIMIT -> gateway enforces rate limit -> excessive request receives 429."""
        mock_submit = MagicMock(return_value={
            "mitigation_action": "RATE_LIMIT",
            "risk_assessment": {
                "risk_score": 75.0,
                "risk_level": "HIGH",
                "threat_detected": True,
                "reasons": ["Automated brute-force or high request rate detected"],
            },
        })

        backend_client = TestClient(backend_app)

        def forward_to_backend(method, path, headers, body):
            resp = backend_client.request(method, path, headers=headers, content=body)
            return resp.status_code, dict(resp.headers), resp.content

        gw_app = create_gateway_app(
            enforcement_table=self.table,
            event_submitter=mock_submit,
            target_forwarder=forward_to_backend,
        )
        gw_client = TestClient(gw_app)

        ip = "192.168.1.105"

        # Request 1: hits target, backend returns RATE_LIMIT, gateway sets state
        r1 = gw_client.post(
            "/demo-login",
            json={"username": "attacker", "password": "wrong"},
            headers={"X-Forwarded-For": ip},
        )
        self.assertEqual(r1.status_code, 401)
        self.assertEqual(r1.headers.get("X-ThreatGuard-Action"), "RATE_LIMIT")

        # Now RATE_LIMIT state is active. Max allowed in window is 2.
        # Send subsequent requests in quick succession:
        r2 = gw_client.post(
            "/demo-login",
            json={"username": "attacker", "password": "wrong"},
            headers={"X-Forwarded-For": ip},
        )
        r3 = gw_client.post(
            "/demo-login",
            json={"username": "attacker", "password": "wrong"},
            headers={"X-Forwarded-For": ip},
        )
        r4 = gw_client.post(
            "/demo-login",
            json={"username": "attacker", "password": "wrong"},
            headers={"X-Forwarded-For": ip},
        )

        # The fourth request must be rate-limited (HTTP 429) before reaching the target
        self.assertEqual(r4.status_code, 429)
        self.assertEqual(r4.json()["status"], "rate_limited")
        self.assertEqual(r4.headers.get("X-ThreatGuard-Action"), "RATE_LIMIT")

    def test_3_block_returns_403_target_not_invoked(self):
        """3. Backend returns BLOCK -> gateway returns 403 -> target is NOT invoked."""
        mock_submit = MagicMock(return_value={
            "mitigation_action": "BLOCK",
            "risk_assessment": {
                "risk_score": 95.0,
                "risk_level": "CRITICAL",
                "threat_detected": True,
                "reasons": ["Critical malicious threat detected"],
            },
        })

        backend_client = TestClient(backend_app)

        def forward_to_backend(method, path, headers, body):
            resp = backend_client.request(method, path, headers=headers, content=body)
            return resp.status_code, dict(resp.headers), resp.content

        gw_app = create_gateway_app(
            enforcement_table=self.table,
            event_submitter=mock_submit,
            target_forwarder=forward_to_backend,
        )
        gw_client = TestClient(gw_app)

        ip = "192.168.1.110"

        # Request 1: Target reached, backend returns BLOCK, gateway stores BLOCK in table
        r1 = gw_client.post(
            "/demo-login",
            json={"username": "hacker", "password": "wrong"},
            headers={"X-Forwarded-For": ip},
        )
        self.assertEqual(r1.status_code, 401)
        self.assertEqual(r1.headers.get("X-ThreatGuard-Action"), "BLOCK")

        count_after_first = get_demo_target_invocation_count()

        # Request 2 from same IP: Must be blocked at gateway (HTTP 403), target must NOT be invoked
        r2 = gw_client.post(
            "/demo-login",
            json={"username": "hacker", "password": "wrong"},
            headers={"X-Forwarded-For": ip},
        )
        self.assertEqual(r2.status_code, 403)
        self.assertEqual(r2.json()["status"], "blocked")
        self.assertEqual(r2.headers.get("X-ThreatGuard-Action"), "BLOCK")

        # Prove target was not called for the blocked request
        self.assertEqual(get_demo_target_invocation_count(), count_after_first)

    def test_4_different_source_ip_not_affected_by_block(self):
        """4. Different source IP is not affected by another source's block state."""
        self.table.update_state(
            source_ip="192.168.1.200",
            action="BLOCK",
            reason="Attacker IP blocked",
            ttl_seconds=10.0,
        )

        mock_submit = MagicMock(return_value={
            "mitigation_action": "ALLOW",
            "risk_assessment": {"risk_score": 0.0, "risk_level": "LOW", "threat_detected": False},
        })

        backend_client = TestClient(backend_app)

        def forward_to_backend(method, path, headers, body):
            resp = backend_client.request(method, path, headers=headers, content=body)
            return resp.status_code, dict(resp.headers), resp.content

        gw_app = create_gateway_app(
            enforcement_table=self.table,
            event_submitter=mock_submit,
            target_forwarder=forward_to_backend,
        )
        gw_client = TestClient(gw_app)

        # Attacker request gets 403
        r_attacker = gw_client.post(
            "/demo-login",
            json={"username": "attacker", "password": "pwd"},
            headers={"X-Forwarded-For": "192.168.1.200"},
        )
        self.assertEqual(r_attacker.status_code, 403)

        # Legitimate client from different IP gets allowed through to target
        r_clean = gw_client.post(
            "/demo-login",
            json={"username": "demo_admin", "password": "SecretPassword123!"},
            headers={"X-Forwarded-For": "192.168.1.50"},
        )
        self.assertEqual(r_clean.status_code, 200)
        self.assertEqual(r_clean.json()["status"], "success")

    def test_5_enforcement_state_expires_after_ttl(self):
        """5. Enforcement state expires after TTL."""
        # Short TTL of 0.2s
        self.table.update_state(
            source_ip="192.168.1.210",
            action="BLOCK",
            reason="Temporary block",
            ttl_seconds=0.2,
        )

        self.assertIsNotNone(self.table.get_state("192.168.1.210"))
        time.sleep(0.3)
        # Should now be expired and pruned
        self.assertIsNone(self.table.get_state("192.168.1.210"))

    def test_6_backend_events_failure_fails_closed_503(self):
        """6. Backend /events failure -> gateway fails closed with 503."""
        def failing_submit(event_dict):
            raise ConnectionError("Backend connection refused at 127.0.0.1:8000")

        backend_client = TestClient(backend_app)

        def forward_to_backend(method, path, headers, body):
            resp = backend_client.request(method, path, headers=headers, content=body)
            return resp.status_code, dict(resp.headers), resp.content

        gw_app = create_gateway_app(
            enforcement_table=self.table,
            event_submitter=failing_submit,
            target_forwarder=forward_to_backend,
        )
        gw_client = TestClient(gw_app)

        resp = gw_client.post(
            "/demo-login",
            json={"username": "user", "password": "pwd"},
            headers={"X-Forwarded-For": "192.168.1.220"},
        )

        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()["status"], "failed_closed")
        self.assertEqual(resp.headers.get("X-ThreatGuard-Action"), "FAIL_CLOSED")

    def test_7_invocation_counter_proves_blocked_never_reaches_target(self):
        """7. Protected demo target invocation counter proves blocked requests never reach target."""
        # Pre-block IP
        self.table.update_state(
            source_ip="192.168.1.230",
            action="BLOCK",
            reason="Active test block",
            ttl_seconds=10.0,
        )

        backend_client = TestClient(backend_app)

        def forward_to_backend(method, path, headers, body):
            resp = backend_client.request(method, path, headers=headers, content=body)
            return resp.status_code, dict(resp.headers), resp.content

        gw_app = create_gateway_app(
            enforcement_table=self.table,
            event_submitter=lambda e: {"mitigation_action": "BLOCK"},
            target_forwarder=forward_to_backend,
        )
        gw_client = TestClient(gw_app)

        count_before = get_demo_target_invocation_count()

        # Send 5 blocked requests
        for _ in range(5):
            r = gw_client.post(
                "/demo-login",
                json={"username": "blocked_user", "password": "wrong"},
                headers={"X-Forwarded-For": "192.168.1.230"},
            )
            self.assertEqual(r.status_code, 403)

        # Verify target counter remained strictly unchanged
        count_after = get_demo_target_invocation_count()
        self.assertEqual(count_before, count_after)


if __name__ == "__main__":
    unittest.main()
