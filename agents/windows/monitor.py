"""
Core monitoring loop for the ThreatGuard Windows Endpoint Agent.

``WindowsEndpointMonitor`` orchestrates telemetry collection, event
submission, and threat notification.
"""
from __future__ import annotations

import logging
import time

from agents.windows.api_client import BackendResponse, WindowsAgentClient
from agents.windows.config import AgentConfig
from agents.windows.notifier import ThreatNotifier
from agents.windows.telemetry import build_demo_event, build_heartbeat_event

logger = logging.getLogger(__name__)


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
        try:
            while self._running:
                self.send_heartbeat_once()
                time.sleep(self.config.heartbeat_interval)
        except KeyboardInterrupt:
            logger.info("Agent stopped by user (Ctrl-C).")
        finally:
            self._running = False

    def send_heartbeat_once(self) -> BackendResponse:
        """Build and submit a single heartbeat event; return the response."""
        event = build_heartbeat_event()
        logger.debug("Sending heartbeat event_id=%s", event.get("event_id"))
        response = self.client.submit_event(event)
        self._handle_backend_response(response, label="HEARTBEAT")
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
        return response

    def stop(self) -> None:
        """Signal the monitoring loop to exit after the current iteration."""
        self._running = False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

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
