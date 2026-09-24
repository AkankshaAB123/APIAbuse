"""
HTTP API client for the ThreatGuard Windows Endpoint Agent.

Handles event submission to the backend ``POST /events`` endpoint and
provides an offline queue so events are not lost when the backend is
temporarily unreachable.
"""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import requests

from agents.windows.config import AgentConfig

logger = logging.getLogger(__name__)


@dataclass
class BackendResponse:
    """Parsed response from the ThreatGuard backend."""

    success: bool
    status_code: int
    threat_detected: bool = False
    risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    attack_types: list[str] = field(default_factory=list)
    mitigation_action: str = "NONE"
    raw: dict = field(default_factory=dict)


class WindowsAgentClient:
    """
    Thin HTTP client that posts events to the ThreatGuard backend.

    When the backend is unavailable, events are stored in a bounded
    in-memory queue and replayed on the next successful connection.
    """

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._queue: deque[dict] = deque(maxlen=config.queue_size)
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        if config.auth_token:
            self._session.headers["Authorization"] = f"Bearer {config.auth_token}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit_event(self, event: dict[str, Any]) -> BackendResponse:
        """
        Submit *event* to the backend.

        If the backend is unreachable the event is queued and a failed
        ``BackendResponse`` is returned.  Any queued events from previous
        failures are flushed first on a successful connection.
        """
        url = f"{self.config.backend_url}/events"
        try:
            resp = self._session.post(
                url, json=event, timeout=self.config.timeout
            )
            resp.raise_for_status()
            result = self._parse_response(resp)
            # Flush offline queue on successful connection
            self._flush_queue()
            return result
        except Exception as exc:  # noqa: BLE001
            logger.warning("Backend unreachable, queuing event: %s", exc)
            self._queue.append(event)
            return BackendResponse(success=False, status_code=0)

    def health_check(self) -> bool:
        """Return True if the backend is reachable."""
        try:
            resp = self._session.get(
                f"{self.config.backend_url}/health",
                timeout=self.config.timeout,
            )
            return resp.status_code < 500
        except requests.RequestException:
            return False

    @property
    def queue_depth(self) -> int:
        """Number of events currently waiting to be flushed."""
        return len(self._queue)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _flush_queue(self) -> None:
        """
        Attempt to send all queued events to the backend.

        On partial failure the unsent tail is restored so events are
        not silently dropped.
        """
        if not self._queue:
            return

        to_send = list(self._queue)
        self._queue.clear()

        url = f"{self.config.backend_url}/events"
        for idx, event in enumerate(to_send):
            try:
                resp = self._session.post(
                    url, json=event, timeout=self.config.timeout
                )
                resp.raise_for_status()
                logger.debug("Flushed queued event successfully.")
            except Exception as exc:  # noqa: BLE001
                logger.warning("Flush failed at event %d: %s", idx, exc)
                # Restore ALL remaining events (current + unsent tail)
                for remaining in to_send[idx:]:
                    self._queue.append(remaining)
                return

    @staticmethod
    def _parse_response(resp: requests.Response) -> BackendResponse:
        """Convert a backend HTTP response into a ``BackendResponse``."""
        try:
            data = resp.json()
        except ValueError:
            return BackendResponse(success=True, status_code=resp.status_code)

        ra = data.get("risk_assessment", {})
        return BackendResponse(
            success=True,
            status_code=resp.status_code,
            threat_detected=ra.get("threat_detected", False),
            risk_score=float(ra.get("risk_score", 0.0)),
            risk_level=str(ra.get("risk_level", "UNKNOWN")),
            attack_types=list(ra.get("attack_types", [])),
            mitigation_action=str(data.get("mitigation_action", "NONE")),
            raw=data,
        )
