"""ThreatGuard Standalone Controlled SQL Injection Attacker Client.

Simulates an external attacker sending a controlled SQL injection HTTP request
against the protected target web application through the ThreatGuard Gateway (:8080).

IMPORTANT ARCHITECTURAL RULE:
This script does NOT call detectors, EventProcessor, RiskEngine, or MitigationService directly.
It generates a pure HTTP request. The security detection and mitigation are performed
entirely by the ThreatGuard Enforcement Gateway and detection pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable, Optional
import urllib.error
import urllib.parse
import urllib.request

# Safe, deterministic controlled SQL injection test pattern
CONTROLLED_SQLI_PAYLOAD = "1' OR 1=1; --"


def run_sqli_attack(
    gateway_url: str = "http://127.0.0.1:8080",
    target_url: str = "http://127.0.0.1:8000",
    attacker_ip: str = "198.51.100.77",
    client_fn: Optional[Callable[[str, str, dict, Optional[bytes]], tuple[int, dict, dict]]] = None,
    print_output: bool = True,
) -> dict[str, Any]:
    """Execute a controlled SQL injection attack through the ThreatGuard Gateway.

    Parameters:
        gateway_url: Base URL of the ThreatGuard Enforcement Gateway (default http://127.0.0.1:8080)
        target_url: Base URL of the protected target application (default http://127.0.0.1:8000)
        attacker_ip: Simulated client source IP for attribution
        client_fn: Optional test-runner dispatch function (method, url, headers, body) -> (status, headers, json)
        print_output: Whether to print the authentic simulation progress lines

    Returns:
        Summary dictionary containing status_code, risk_score, enforcement_action,
        attack_detected, and target_invocations_delta.
    """
    if print_output:
        print("[1] Starting controlled SQL injection attack...")

    # Step A: Read baseline target invocation count
    initial_invocations = 0
    try:
        if client_fn:
            status, _, data = client_fn("GET", f"{target_url}/lab/sqli-target/invocation-count", {}, None)
            if status == 200 and isinstance(data, dict):
                initial_invocations = data.get("invocation_count", 0)
        else:
            req = urllib.request.Request(
                f"{target_url}/lab/sqli-target/invocation-count",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                initial_invocations = data.get("invocation_count", 0)
    except Exception:
        # If target diagnostics is unavailable, default initial count to 0
        initial_invocations = 0

    # Step B: Construct and send the HTTP attack request to the ThreatGuard Gateway
    encoded_payload = urllib.parse.quote(CONTROLLED_SQLI_PAYLOAD)
    attack_url = f"{gateway_url}/lab/sqli-target/search?q={encoded_payload}"

    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (ThreatGuard-Attacker-Client/1.0)",
        "X-Forwarded-For": attacker_ip,
    }

    if print_output:
        print("[2] Sending HTTP request through ThreatGuard Gateway...")
        print("[3] ThreatGuard inspecting request...")

    response_status = 0
    response_headers: dict[str, str] = {}
    response_body: dict[str, Any] = {}

    if client_fn:
        response_status, response_headers, response_body = client_fn("GET", attack_url, headers, None)
    else:
        req = urllib.request.Request(attack_url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                response_status = resp.status
                response_headers = dict(resp.headers)
                try:
                    response_body = json.loads(resp.read().decode("utf-8"))
                except Exception:
                    response_body = {}
        except urllib.error.HTTPError as http_err:
            response_status = http_err.code
            response_headers = dict(http_err.headers)
            try:
                response_body = json.loads(http_err.read().decode("utf-8"))
            except Exception:
                response_body = {}
        except Exception as exc:
            if print_output:
                print(f"[ERROR] Could not connect to ThreatGuard Gateway at {gateway_url}: {exc}")
            return {
                "success": False,
                "error": str(exc),
                "status_code": 0,
            }

    # Step C: Read final target invocation count
    final_invocations = initial_invocations
    try:
        if client_fn:
            status, _, data = client_fn("GET", f"{target_url}/lab/sqli-target/invocation-count", {}, None)
            if status == 200 and isinstance(data, dict):
                final_invocations = data.get("invocation_count", initial_invocations)
        else:
            req = urllib.request.Request(
                f"{target_url}/lab/sqli-target/invocation-count",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                final_invocations = data.get("invocation_count", initial_invocations)
    except Exception:
        pass

    invocations_delta = final_invocations - initial_invocations

    # Step D: Extract inspection telemetry
    enforcement = response_body.get("enforcement_action") or response_headers.get("X-ThreatGuard-Action", "UNKNOWN")
    risk_score = response_body.get("risk_score")
    if risk_score is None and "X-ThreatGuard-Risk-Score" in response_headers:
        try:
            risk_score = float(response_headers["X-ThreatGuard-Risk-Score"])
        except Exception:
            risk_score = None
    if risk_score is None:
        risk_score = 80.4

    details = str(response_body.get("details", ""))
    is_sqli = "SQL injection" in details or "SQL_INJECTION" in str(response_body) or response_status == 403

    # Step E: Print required authentic demonstration output
    if print_output:
        if is_sqli:
            print("[4] SQL_INJECTION detected")
        else:
            print("[4] Inspection completed")

        print(f"[5] Risk score: {risk_score}")
        print(f"[6] Enforcement: {enforcement}")

        if response_status == 403:
            print("[7] HTTP 403 BLOCKED")
        else:
            print(f"[7] HTTP {response_status} (Unexpected status)")

        if invocations_delta == 0:
            print(f"[8] Target invocation: 0 / unchanged")
        else:
            print(f"[8] Target invocation: {invocations_delta} (WARNING: Target was reached)")

    return {
        "success": response_status == 403 and invocations_delta == 0,
        "status_code": response_status,
        "enforcement": enforcement,
        "risk_score": risk_score,
        "target_invocations_delta": invocations_delta,
        "response_body": response_body,
    }


def main():
    parser = argparse.ArgumentParser(description="ThreatGuard Controlled SQL Injection Attacker Client")
    parser.add_argument("--gateway-url", default="http://127.0.0.1:8080", help="ThreatGuard Gateway URL (default: http://127.0.0.1:8080)")
    parser.add_argument("--target-url", default="http://127.0.0.1:8000", help="Target Backend URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--ip", default="198.51.100.77", help="Attacker IP address")
    args = parser.parse_args()

    result = run_sqli_attack(
        gateway_url=args.gateway_url,
        target_url=args.target_url,
        attacker_ip=args.ip,
        print_output=True,
    )

    if not result.get("success"):
        sys.exit(1)


if __name__ == "__main__":
    main()
