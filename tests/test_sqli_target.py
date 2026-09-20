"""Comprehensive Tests for Controlled SQL Injection Target & Gateway Interception (Option B).

Verifies:
1. Direct target access (/lab/sqli-target) returns authentic e-commerce catalog UI.
2. Target UI contains NO attack buttons, NO SQLi buttons, NO presets, and NO hardcoded attack indicators.
3. Direct benign search (/lab/sqli-target/search?q=laptop) returns 200 and increments invocation counter.
4. Gateway integration - Option B:
   a. Normal request (GET /lab/sqli-target/search?q=laptop) through gateway:
      - Intercepted by gateway, query parameters included in telemetry.
      - EventProcessor evaluates event -> ALLOW.
      - Gateway forwards request with query string to target.
      - HTTP 200 OK returned to client with product catalog.
      - Target invocation counter is incremented.
   b. SQL Injection attack (GET /lab/sqli-target/search?q=1' OR 1=1; --) through gateway:
      - Intercepted by gateway, query parameters included in telemetry.
      - EventProcessor evaluates event -> SQL Injection detected (Risk HIGH).
      - MitigationService decides active defense (BLOCK).
      - Gateway blocks with HTTP 403 Forbidden.
      - Target invocation counter is NOT incremented (proves target was never reached).
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.routes.sqli_target import (
    get_sqli_target_invocation_count,
    reset_sqli_target_invocation_count,
)
from backend.services.event_processor import EventProcessor
from gateway.enforcement_table import EnforcementTable
from gateway.proxy import GatewayConfig, create_gateway_app
from tests.simulate_sqli_attack import run_sqli_attack, CONTROLLED_SQLI_PAYLOAD


class SqliTargetAndGatewayOptionBTests(unittest.TestCase):

    def setUp(self):
        reset_sqli_target_invocation_count()

    def tearDown(self):
        reset_sqli_target_invocation_count()

    # -------------------------------------------------------------------------
    # 1. Target Web Application Unit Tests
    # -------------------------------------------------------------------------

    def test_1_target_home_renders_clean_store_ui(self):
        """Direct GET /lab/sqli-target returns authentic TechGear catalog HTML."""
        client = TestClient(app)
        response = client.get("/lab/sqli-target")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("content-type", ""))
        self.assertIn("TechGear Store", response.text)
        self.assertIn("Enterprise Hardware & Peripherals", response.text)
        self.assertIn("UltraBook Pro 15", response.text)

        # Ensure target UI contains NO attack buttons, presets, or simulator text
        self.assertNotIn("Run SQL Injection Simulation", response.text)
        self.assertNotIn("Attack Simulator", response.text)
        self.assertNotIn("ThreatGuard Active Defense", response.text)
        self.assertNotIn("payload", response.text.lower())

    def test_2_target_search_increments_invocation_counter(self):
        """Direct benign search returns 200 and increments invocation counter."""
        client = TestClient(app)
        self.assertEqual(get_sqli_target_invocation_count(), 0)

        response = client.get("/lab/sqli-target/search?q=laptop")
        self.assertEqual(response.status_code, 200)
        self.assertIn("UltraBook Pro 15", response.text)
        self.assertEqual(get_sqli_target_invocation_count(), 1)

    def test_3_target_search_json_response(self):
        """Direct search with Accept: application/json returns filtered products."""
        client = TestClient(app)
        response = client.get(
            "/lab/sqli-target/search?q=monitor",
            headers={"Accept": "application/json"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["query"], "monitor")
        self.assertEqual(len(data["items"]), 1)
        self.assertEqual(data["items"][0]["name"], "VisionPro 27-Inch 4K Display")
        self.assertEqual(get_sqli_target_invocation_count(), 1)

    # -------------------------------------------------------------------------
    # 2. Gateway Option B Interception Tests
    # -------------------------------------------------------------------------

    def _build_test_gateway_client(self):
        """Build gateway test harness with direct in-memory EventProcessor and target forwarder."""
        processor = EventProcessor()
        target_client = TestClient(app)

        def mock_submit_event(event_dict: dict) -> dict:
            # Process via existing ThreatGuard EventProcessor
            from backend.schemas.api_security_event import ApiSecurityEvent
            event_obj = ApiSecurityEvent(**event_dict)
            result = processor.process(event=event_obj)
            return {
                "mitigation_action": result.mitigation_action,
                "risk_assessment": {
                    "threat_detected": result.risk_assessment.threat_detected,
                    "risk_score": result.risk_assessment.risk_score,
                    "risk_level": result.risk_assessment.risk_level,
                    "reasons": result.risk_assessment.reasons,
                    "attack_types": result.risk_assessment.attack_types,
                },
            }

        def mock_forward_target(method: str, path: str, headers: dict, body: bytes) -> tuple[int, dict, bytes]:
            # Forward directly to target FastAPI application
            resp = target_client.request(
                method=method,
                url=path,
                headers={k: v for k, v in headers.items() if k.lower() not in ("content-length",)},
                content=body if body else None,
            )
            return resp.status_code, dict(resp.headers), resp.content

        gw_config = GatewayConfig(
            target_base_url="http://127.0.0.1:8000",
            backend_events_url="http://127.0.0.1:8000/events",
            protected_host="127.0.0.1",
        )
        gw_table = EnforcementTable()
        gw_app = create_gateway_app(
            config=gw_config,
            enforcement_table=gw_table,
            event_submitter=mock_submit_event,
            target_forwarder=mock_forward_target,
        )
        return TestClient(gw_app)

    def test_4_gateway_allows_benign_search_and_forwards_query(self):
        """Option B: Normal user search through gateway forwards query and reaches target."""
        gw_client = self._build_test_gateway_client()
        self.assertEqual(get_sqli_target_invocation_count(), 0)

        # User searches for 'mouse' through ThreatGuard gateway
        response = gw_client.get(
            "/lab/sqli-target/search?q=mouse",
            headers={"X-Forwarded-For": "192.168.1.150"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("ProWireless Precision Mouse", response.text)
        self.assertEqual(response.headers.get("X-ThreatGuard-Action"), "ALLOW")

        # Crucial verification: Target application WAS reached once
        self.assertEqual(get_sqli_target_invocation_count(), 1)

    def test_5_gateway_blocks_sqli_and_target_is_never_reached(self):
        """Option B: Malicious search through gateway is blocked (403); target invocation count remains 0."""
        gw_client = self._build_test_gateway_client()
        self.assertEqual(get_sqli_target_invocation_count(), 0)

        # Attacker injects SQLi via query param 'q' through ThreatGuard gateway
        sqli_query = "1' OR 1=1; --"
        response = gw_client.get(
            f"/lab/sqli-target/search?q={sqli_query}",
            headers={"X-Forwarded-For": "192.168.1.205"},
        )

        # Verify gateway blocked the request with 403 Forbidden
        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertEqual(data["status"], "blocked")
        self.assertEqual(data["error"], "access_forbidden")
        self.assertIn(data["enforcement_action"], ("RATE_LIMIT", "BLOCK"))
        self.assertEqual(data["risk_level"], "HIGH")

        # CRITICAL VERIFICATION: Target application was NEVER reached!
        self.assertEqual(
            get_sqli_target_invocation_count(),
            0,
            "Target application must NOT be invoked when SQL injection is intercepted by the gateway.",
        )

    def test_6_gateway_blocks_union_select_sqli_and_preserves_target_isolation(self):
        """Option B: UNION SELECT injection is intercepted and target remains untouched."""
        gw_client = self._build_test_gateway_client()
        self.assertEqual(get_sqli_target_invocation_count(), 0)

        union_query = "1' UNION SELECT username, password FROM users; --"
        response = gw_client.get(
            f"/lab/sqli-target/search?q={union_query}",
            headers={"X-Forwarded-For": "192.168.1.210"},
        )

        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertEqual(data["status"], "blocked")
        self.assertIn("SQL injection", data["details"])

        # Target remains untouched
        self.assertEqual(get_sqli_target_invocation_count(), 0)

    def test_7_gateway_subsequent_blocked_ip_rejected_before_pipeline(self):
        """After SQLi block, subsequent requests from the same IP are immediately rejected."""
        gw_client = self._build_test_gateway_client()

        # Step 1: Trigger SQLi
        resp1 = gw_client.get(
            "/lab/sqli-target/search?q=1' OR 1=1; --",
            headers={"X-Forwarded-For": "192.168.1.220"},
        )
        self.assertEqual(resp1.status_code, 403)

        # Step 2: Same IP tries benign search
        resp2 = gw_client.get(
            "/lab/sqli-target/search?q=laptop",
            headers={"X-Forwarded-For": "192.168.1.220"},
        )
        self.assertEqual(resp2.status_code, 403)
        self.assertEqual(resp2.json()["status"], "blocked")

        # Target was NEVER invoked across either request
        self.assertEqual(get_sqli_target_invocation_count(), 0)

    def test_8_separate_attacker_client_executes_sqli_via_gateway(self):
        """Verify the standalone attacker client generates real HTTP requests intercepted by ThreatGuard."""
        gw_client = self._build_test_gateway_client()
        target_client = TestClient(app)

        self.assertEqual(get_sqli_target_invocation_count(), 0)

        # Wire client_fn to dispatch through the gateway test client
        def custom_client_dispatch(method: str, url: str, headers: dict, body: bytes):
            # Route to either gateway or target depending on URL
            if ":8000" in url:
                # Diagnostics/target request
                path = url.split(":8000")[1]
                resp = target_client.request(method, path, headers=headers)
                return resp.status_code, dict(resp.headers), resp.json() if "json" in resp.headers.get("content-type", "") else {}
            else:
                # Gateway attack request
                path = url.split(":8080")[1] if ":8080" in url else url
                resp = gw_client.request(method, path, headers=headers)
                return resp.status_code, dict(resp.headers), resp.json() if "json" in resp.headers.get("content-type", "") else {}

        # Run standalone attacker simulation function
        result = run_sqli_attack(
            gateway_url="http://127.0.0.1:8080",
            target_url="http://127.0.0.1:8000",
            attacker_ip="198.51.100.99",
            client_fn=custom_client_dispatch,
            print_output=True,
        )

        # 1. Attacker client generated HTTP request and gateway returned HTTP 403
        self.assertEqual(result["status_code"], 403)
        self.assertTrue(result["success"])

        # 2. RiskEngine was exercised
        self.assertAlmostEqual(result["risk_score"], 80.4, places=1)

        # 3. Mitigation/Enforcement was exercised
        self.assertEqual(result["enforcement"], "BLOCK")

        # 4. Crucial: Target was NOT reached (delta == 0)
        self.assertEqual(result["target_invocations_delta"], 0)
        self.assertEqual(get_sqli_target_invocation_count(), 0)

    def test_9_normal_browser_catalog_browsing_remains_benign(self):
        """Innocent user browsing catalog through gateway receives 200 and invokes target."""
        gw_client = self._build_test_gateway_client()
        self.assertEqual(get_sqli_target_invocation_count(), 0)

        # Step 1: User opens catalog home
        home_resp = gw_client.get(
            "/lab/sqli-target",
            headers={"X-Forwarded-For": "192.168.1.188"},
        )
        self.assertEqual(home_resp.status_code, 200)
        self.assertIn("TechGear Store", home_resp.text)

        # Step 2: User searches for keyboard
        search_resp = gw_client.get(
            "/lab/sqli-target/search?q=keyboard",
            headers={"X-Forwarded-For": "192.168.1.188"},
        )
        self.assertEqual(search_resp.status_code, 200)
        self.assertIn("MechKey Studio 87", search_resp.text)
        self.assertEqual(get_sqli_target_invocation_count(), 1)


if __name__ == "__main__":
    unittest.main()
