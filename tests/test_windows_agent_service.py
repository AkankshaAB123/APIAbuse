"""
Unit tests for the ThreatGuard Windows Endpoint Agent Service and Configuration.

Tests persistent configuration loading/saving, service command construction,
logging configuration, and status formatting without requiring actual Windows Service
administrative installation.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agents.windows.config import AgentConfig
from agents.windows.device import get_device_id
from agents.windows.logging_config import setup_agent_logging
from agents.windows.service import (
    _get_agent_binary_command,
    format_status_output,
    get_service_status,
    install_service,
    start_service,
    stop_service,
    uninstall_service,
)


class TestConfigPersistence:
    def test_save_and_load_config(self, tmp_path):
        """Configuration can be saved to JSON and reloaded accurately."""
        cfg_path = tmp_path / "config.json"
        cfg = AgentConfig(
            backend_url="http://192.168.1.55:8000",
            heartbeat_interval=45,
            timeout=12.0,
            queue_size=80,
            auth_token="jwt-token-123",
            log_level="DEBUG",
        )
        saved_path = cfg.save(cfg_path)
        assert saved_path == cfg_path
        assert cfg_path.exists()

        # Reload from the saved file
        loaded = AgentConfig.load(cfg_path)
        assert loaded.backend_url == "http://192.168.1.55:8000"
        assert loaded.heartbeat_interval == 45
        assert loaded.timeout == 12.0
        assert loaded.queue_size == 80
        assert loaded.auth_token == "jwt-token-123"
        assert loaded.log_level == "DEBUG"

    def test_env_overrides_file_config(self, tmp_path):
        """Environment variables take precedence over config file values."""
        cfg_path = tmp_path / "config.json"
        cfg = AgentConfig(backend_url="http://original-server:8000")
        cfg.save(cfg_path)

        with patch.dict(
            "os.environ",
            {"THREATGUARD_SERVER_URL": "http://override-server:9000"},
        ):
            loaded = AgentConfig.load(cfg_path)
            assert loaded.backend_url == "http://override-server:9000"


class TestServiceManagementCommands:
    @patch("subprocess.run")
    def test_install_service_command(self, mock_run):
        """install_service executes sc.exe create and configuration calls."""
        mock_run.return_value = MagicMock(returncode=0, stdout="[SC] CreateService SUCCESS", stderr="")
        with patch.object(AgentConfig, "save"):
            ok, msg = install_service(backend_url="http://10.0.0.1:8000")

        assert ok is True
        assert "installed successfully" in msg
        assert mock_run.call_count >= 1

        # Check sc.exe arguments
        first_call_args = mock_run.call_args_list[0][0][0]
        assert first_call_args[0] == "sc.exe"
        assert first_call_args[1] == "create"
        assert first_call_args[2] == "ThreatGuardAgent"
        assert "start= auto" in " ".join(first_call_args)

    @patch("subprocess.run")
    def test_start_service_command(self, mock_run):
        """start_service executes sc.exe start."""
        mock_run.return_value = MagicMock(returncode=0, stdout="SERVICE_START_PENDING", stderr="")
        ok, msg = start_service()
        assert ok is True
        assert "started successfully" in msg

    @patch("subprocess.run")
    def test_stop_service_command(self, mock_run):
        """stop_service executes sc.exe stop."""
        mock_run.return_value = MagicMock(returncode=0, stdout="SERVICE_STOP_PENDING", stderr="")
        ok, msg = stop_service()
        assert ok is True
        assert "stopped successfully" in msg

    @patch("subprocess.run")
    def test_uninstall_service_command(self, mock_run):
        """uninstall_service attempts stop and delete via sc.exe."""
        mock_run.return_value = MagicMock(returncode=0, stdout="[SC] DeleteService SUCCESS", stderr="")
        ok, msg = uninstall_service()
        assert ok is True
        assert "uninstalled successfully" in msg

    def test_binary_command_format(self):
        """Binary command line string includes appropriate service-run flag."""
        cmd = _get_agent_binary_command()
        assert "--service-run" in cmd


class TestStatusFormatting:
    def test_status_formatting_output(self):
        """Status dict is formatted into clean human-readable output."""
        status_data = {
            "service_name": "ThreatGuardAgent",
            "service_state": "RUNNING",
            "device_id": "WIN-TESTDEVICE1234",
            "server_url": "http://127.0.0.1:8000",
            "last_heartbeat": "2026-09-24T00:00:00Z",
            "last_event_type": "heartbeat",
            "last_mitigation": "ALLOW",
            "queue_size": 0,
            "log_file": r"C:\ProgramData\ThreatGuard\logs\agent.log",
        }
        formatted = format_status_output(status_data)
        assert "ThreatGuard Windows Endpoint Agent" in formatted
        assert "RUNNING" in formatted
        assert "WIN-TESTDEVICE1234" in formatted
        assert "http://127.0.0.1:8000" in formatted
        assert "ALLOW" in formatted


class TestLoggingSetup:
    def test_logging_setup_creates_handlers(self, tmp_path):
        """Logging configuration sets up root logger with file and console handlers."""
        log_file = tmp_path / "test_agent.log"
        logger = setup_agent_logging(log_file=log_file, log_level="DEBUG", console=True)
        assert logger is not None
        assert any(
            hasattr(h, "baseFilename") and str(log_file) in h.baseFilename
            for h in logger.handlers
        )
