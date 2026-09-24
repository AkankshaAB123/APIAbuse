"""
Unit tests for the ThreatGuard Windows Endpoint Agent.

Tests are fully offline — no network calls are made.  The backend is
mocked via ``unittest.mock`` so tests pass without a running server.

Run:
    .venv\\Scripts\\python.exe -m pytest tests/test_windows_agent.py -v
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure repo root is on sys.path when running from project root
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from agents.windows.api_client import BackendResponse, WindowsAgentClient
from agents.windows.config import AgentConfig
from agents.windows.device import _compute_device_id, get_device_id
from agents.windows.monitor import WindowsEndpointMonitor
from agents.windows.notifier import ThreatNotifier
from agents.windows.telemetry import build_demo_event, build_heartbeat_event


# ===========================================================================
# 1. Device identity
# ===========================================================================

class TestDeviceIdentity:
    def test_device_id_format(self):
        """Device ID must match WIN-<16 hex chars>."""
        device_id = _compute_device_id()
        assert device_id.startswith("WIN-"), f"Expected 'WIN-' prefix, got: {device_id}"
        suffix = device_id[4:]
        assert len(suffix) == 16, f"Expected 16-char suffix, got {len(suffix)}: {suffix}"
        assert suffix == suffix.upper(), "Suffix must be uppercase hex"

    def test_device_id_persistence(self, tmp_path):
        """Device ID is stable across calls when cached."""
        cache_file = tmp_path / "device_id"

        with (
            patch("agents.windows.device._CACHE_DIR", tmp_path),
            patch("agents.windows.device._CACHE_FILE", cache_file),
        ):
            id1 = get_device_id()
            id2 = get_device_id()

        assert id1 == id2, "Device ID must be stable across calls"
        assert cache_file.exists(), "Cache file must be written"
        assert cache_file.read_text().strip() == id1


# ===========================================================================
# 2. Configuration
# ===========================================================================

class TestAgentConfig:
    def test_defaults(self):
        """Defaults are applied when no env vars are set."""
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("THREATGUARD_")}
        with patch.dict(os.environ, env, clear=True):
            cfg = AgentConfig.from_env()
        assert cfg.backend_url == "http://127.0.0.1:8000"
        assert cfg.heartbeat_interval == 30
        assert cfg.timeout == 8.0
        assert cfg.queue_size == 50
        assert cfg.auth_token is None

    def test_env_overrides(self):
        """Environment variables override defaults."""
        overrides = {
            "THREATGUARD_BACKEND_URL": "http://10.0.0.1:9000",
            "THREATGUARD_HEARTBEAT_INTERVAL": "60",
            "THREATGUARD_TIMEOUT": "15.0",
            "THREATGUARD_QUEUE_SIZE": "100",
            "THREATGUARD_AUTH_TOKEN": "tok-abc123",
        }
        with patch.dict(os.environ, overrides):
            cfg = AgentConfig.from_env()
        assert cfg.backend_url == "http://10.0.0.1:9000"
        assert cfg.heartbeat_interval == 60
        assert cfg.timeout == 15.0
        assert cfg.queue_size == 100
        assert cfg.auth_token == "tok-abc123"


# ===========================================================================
# 3. Telemetry builders
# ===========================================================================

class TestTelemetryBuilders:
    def test_heartbeat_event_structure(self):
        """Heartbeat event has required fields and correct domain/event_type."""
        event = build_heartbeat_event()
        assert event["schema_version"] == "1.0"
        assert event["domain"] == "ENDPOINT"
        assert event["endpoint"]["event_type"] == "heartbeat"
        assert event["event_id"]
        assert event["timestamp"]
        assert "network" in event
        assert "identity" in event
        assert "request" in event
        assert "response" in event

    def test_demo_event_structure(self):
        """Demo event simulates a suspicious PowerShell process creation."""
        event = build_demo_event()
        assert event["domain"] == "ENDPOINT"
        ep = event["endpoint"]
        assert ep["event_type"] == "process_creation"
        assert ep["process_name"] == "powershell.exe"
        assert "-enc" in ep["command_line"]
        assert ep["elevated"] is True
        assert ep["network_connection"] is True


# ===========================================================================
# 4. API client — success path
# ===========================================================================

class TestWindowsAgentClientSuccess:
    def _make_client(self, queue_size: int = 10) -> WindowsAgentClient:
        cfg = AgentConfig(backend_url="http://mock:8000", queue_size=queue_size)
        return WindowsAgentClient(cfg)

    def _mock_response(self, data: dict, status: int = 200) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.status_code = status
        mock_resp.json.return_value = data
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def test_event_submission_success(self):
        """Successful submission returns threat_detected=True for a risky event."""
        backend_payload = {
            "risk_assessment": {
                "threat_detected": True,
                "risk_score": 93.4,
                "risk_level": "CRITICAL",
                "attack_types": ["SUSPICIOUS_PROCESS_EXECUTION", "REVERSE_SHELL"],
            },
            "mitigation_action": "QUARANTINE",
        }
        client = self._make_client()

        with patch.object(client._session, "post", return_value=self._mock_response(backend_payload)):
            resp = client.submit_event(build_demo_event())

        assert resp.success is True
        assert resp.threat_detected is True
        assert resp.risk_score == pytest.approx(93.4)
        assert resp.risk_level == "CRITICAL"
        assert "REVERSE_SHELL" in resp.attack_types
        assert resp.mitigation_action == "QUARANTINE"


# ===========================================================================
# 5. API client — offline queue
# ===========================================================================

class TestWindowsAgentClientOfflineQueue:
    def _make_client(self, queue_size: int = 5) -> WindowsAgentClient:
        cfg = AgentConfig(backend_url="http://mock:8000", queue_size=queue_size)
        return WindowsAgentClient(cfg)

    def test_backend_unavailable_enqueues_event(self):
        """Events are queued when backend is unreachable."""
        client = self._make_client()

        with patch.object(
            client._session, "post", side_effect=Exception("Connection refused")
        ):
            resp = client.submit_event(build_heartbeat_event())

        assert resp.success is False
        assert client.queue_depth == 1

    def test_bounded_queue_limits_memory(self):
        """Queue must not exceed maxlen; oldest events are silently dropped."""
        max_q = 3
        client = self._make_client(queue_size=max_q)

        with patch.object(
            client._session, "post", side_effect=Exception("offline")
        ):
            for _ in range(max_q + 5):
                client.submit_event(build_heartbeat_event())

        assert client.queue_depth == max_q, (
            f"Queue depth {client.queue_depth} exceeds maxlen {max_q}"
        )


# ===========================================================================
# 6. Notifier state transitions
# ===========================================================================

class TestThreatNotifier:
    def test_no_output_when_backend_failed(self, capsys):
        """No output for a failed (offline) response."""
        notifier = ThreatNotifier(toast_enabled=False)
        failed = BackendResponse(success=False, status_code=0)
        notifier.notify(failed)
        out = capsys.readouterr().out
        assert out == ""

    def test_safe_message_when_no_threat(self, capsys):
        """PROTECTED message printed for safe responses."""
        notifier = ThreatNotifier(toast_enabled=False)
        safe = BackendResponse(success=True, status_code=200, threat_detected=False, risk_score=10.0)
        notifier.notify(safe)
        out = capsys.readouterr().out
        assert "PROTECTED" in out

    def test_alert_message_when_threat(self, capsys):
        """THREAT DETECTED banner printed for malicious responses."""
        notifier = ThreatNotifier(toast_enabled=False)
        threat = BackendResponse(
            success=True,
            status_code=200,
            threat_detected=True,
            risk_score=93.4,
            risk_level="CRITICAL",
            attack_types=["REVERSE_SHELL"],
            mitigation_action="QUARANTINE",
        )
        notifier.notify(threat)
        out = capsys.readouterr().out
        assert "THREAT DETECTED" in out
        assert "REVERSE_SHELL" in out
        assert "QUARANTINE" in out
