"""
Core monitoring loop for the ThreatGuard Windows Endpoint Agent.

``WindowsEndpointMonitor`` orchestrates telemetry collection, event
submission, and threat notification.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import time
from pathlib import Path

from agents.windows.api_client import BackendResponse, WindowsAgentClient
from agents.windows.config import AgentConfig
from agents.windows.device import get_device_id
from agents.windows.notifier import ThreatNotifier
from agents.windows.telemetry import build_demo_event, build_heartbeat_event

logger = logging.getLogger(__name__)

SYSTEM_STATUS_FILE = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "ThreatGuard" / "runtime_status.json"
USER_STATUS_FILE = Path.home() / ".threatguard" / "runtime_status.json"


class WindowsEndpointMonitor:
    """
    Coordinates the heartbeat loop, demo-event injection, and alerting.

    Parameters
    ----------
    config:
        Runtime configuration (backend URL, intervals, etc.).
    toast_enabled:
        Pass *False* to suppress Windows Toast notifications (useful in tests).
    """

    def __init__(
        self,
        config: AgentConfig | None = None,
        *,
        toast_enabled: bool = True,
    ) -> None:
        self.config = config or AgentConfig.from_env()
        self.client = WindowsAgentClient(self.config)
        self.notifier = ThreatNotifier(toast_enabled=toast_enabled)
        self._running = False

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def run_loop(self) -> None:
        """
        Start the continuous monitoring loop.

        Sends a heartbeat every ``config.heartbeat_interval`` seconds.
        Press Ctrl-C to stop.
        """
        logger.info(
            "ThreatGuard Windows Agent starting — backend=%s interval=%ds",
            self.config.backend_url,
            self.config.heartbeat_interval,
        )
        self._running = True
        self._write_runtime_status(state="RUNNING")
        try:
            while self._running:
                self.send_heartbeat_once()
                # Responsive sleep: check self._running every second
                for _ in range(self.config.heartbeat_interval):
                    if not self._running:
                        break
                    time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Agent stopped by user (Ctrl-C).")
        finally:
            self._running = False
            self._write_runtime_status(state="STOPPED")
            logger.info("ThreatGuard Windows Agent stopped.")

    def send_heartbeat_once(self) -> BackendResponse:
        """Build and submit a single heartbeat event; return the response."""
        event = build_heartbeat_event()
        logger.debug("Sending heartbeat event_id=%s", event.get("event_id"))
        response = self.client.submit_event(event)
        self._handle_backend_response(response, label="HEARTBEAT")
        self._write_runtime_status(state="RUNNING", event_type="heartbeat", response=response)
        return response

    def send_demo_event(self) -> BackendResponse:
        """Build and submit a synthetic high-risk demo event."""
        event = build_demo_event()
        logger.info(
            "Sending DEMO event (process_creation) event_id=%s",
            event.get("event_id"),
        )
        response = self.client.submit_event(event)
        self._handle_backend_response(response, label="DEMO")
        self._write_runtime_status(state="RUNNING", event_type="demo", response=response)
        return response

    def stop(self) -> None:
        """Signal the monitoring loop to exit after the current iteration."""
        self._running = False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _write_runtime_status(
        self,
        state: str = "RUNNING",
        event_type: str = "none",
        response: BackendResponse | None = None,
    ) -> None:
        """Record live runtime status to a lightweight JSON file for CLI queries."""
        payload = {
            "state": state,
            "device_id": get_device_id(),
            "server_url": self.config.backend_url,
            "heartbeat_interval": self.config.heartbeat_interval,
            "queue_size": self.client.queue_depth,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "last_event_type": event_type,
            "last_response_success": response.success if response else None,
            "last_risk_score": response.risk_score if response else None,
            "last_risk_level": response.risk_level if response else None,
            "last_mitigation": response.mitigation_action if response else None,
        }
        for path in (SYSTEM_STATUS_FILE, USER_STATUS_FILE):
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                break
            except OSError:
                continue

    def _handle_backend_response(
        self, response: BackendResponse, *, label: str = ""
    ) -> None:
        prefix = f"[{label}] " if label else ""
        if not response.success:
            logger.warning("%sBackend unreachable — event queued.", prefix)
            print(f"  [WARN] {prefix}Backend unreachable - event queued (depth={self.client.queue_depth})")
            return

        self.notifier.notify(response)

        if response.threat_detected:
            logger.warning(
                "%sTHREAT score=%.1f level=%s attacks=%s mitigation=%s",
                prefix,
                response.risk_score,
                response.risk_level,
                response.attack_types,
                response.mitigation_action,
            )
