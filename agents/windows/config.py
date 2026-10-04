"""
Configuration for the ThreatGuard Windows Endpoint Agent.

Reads settings from persistent JSON configuration (C:\\ProgramData\\ThreatGuard\\config.json),
environment variables (THREATGUARD_SERVER_URL, THREATGUARD_BACKEND_URL), and CLI flags.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_SYSTEM_CONFIG_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "ThreatGuard"
DEFAULT_SYSTEM_CONFIG_FILE = DEFAULT_SYSTEM_CONFIG_DIR / "config.json"
DEFAULT_USER_CONFIG_DIR = Path.home() / ".threatguard"
DEFAULT_USER_CONFIG_FILE = DEFAULT_USER_CONFIG_DIR / "config.json"

DEFAULT_SYSTEM_LOG_DIR = DEFAULT_SYSTEM_CONFIG_DIR / "logs"
DEFAULT_SYSTEM_LOG_FILE = DEFAULT_SYSTEM_LOG_DIR / "agent.log"
DEFAULT_USER_LOG_DIR = DEFAULT_USER_CONFIG_DIR / "logs"
DEFAULT_USER_LOG_FILE = DEFAULT_USER_LOG_DIR / "agent.log"


def get_default_log_file() -> Path:
    """Return default log file path, preferring ProgramData when accessible."""
    if DEFAULT_SYSTEM_LOG_DIR.exists() or os.name == "nt":
        return DEFAULT_SYSTEM_LOG_FILE
    return DEFAULT_USER_LOG_FILE


@dataclass
class AgentConfig:
    """Holds all runtime configuration for the Windows agent."""

    backend_url: str = "http://127.0.0.1:8000"
    heartbeat_interval: int = 30          # seconds between heartbeats
    timeout: float = 8.0                  # HTTP request timeout in seconds
    queue_size: int = 50                  # max offline events buffered
    auth_token: str | None = None
    log_file: str = field(default_factory=lambda: str(get_default_log_file()))
    log_level: str = "INFO"
    device_id: str | None = None

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "AgentConfig":
        """
        Load configuration with layered priority:
        1. Explicit config file if specified
        2. System config file (C:\\ProgramData\\ThreatGuard\\config.json)
        3. User config file (~/.threatguard/config.json)
        4. Environment variables (THREATGUARD_SERVER_URL, THREATGUARD_BACKEND_URL, etc.)
        5. Built-in defaults
        """
        data: dict = {}

        # 1. Candidate config file paths
        candidate_paths = []
        if config_path:
            candidate_paths.append(Path(config_path))
        candidate_paths.extend([DEFAULT_SYSTEM_CONFIG_FILE, DEFAULT_USER_CONFIG_FILE])

        for path in candidate_paths:
            try:
                if path.exists():
                    raw = path.read_text(encoding="utf-8").strip()
                    if raw:
                        parsed = json.loads(raw)
                        if isinstance(parsed, dict):
                            data = parsed
                            logger.debug("Loaded agent configuration from %s", path)
                            break
            except Exception as exc:
                logger.warning("Could not read config from %s: %s", path, exc)

        # 2. Extract values from file data
        backend_url = (
            data.get("backend_url")
            or data.get("server_url")
            or "http://127.0.0.1:8000"
        )
        heartbeat_interval = int(data.get("heartbeat_interval", 30))
        timeout = float(data.get("timeout", 8.0))
        queue_size = int(data.get("queue_size", 50))
        auth_token = data.get("auth_token")
        log_file = data.get("log_file") or str(get_default_log_file())
        log_level = data.get("log_level", "INFO").upper()
        device_id = data.get("device_id")

        # 3. Environment variable overrides (higher priority than config file)
        env_url = os.environ.get("THREATGUARD_SERVER_URL") or os.environ.get("THREATGUARD_BACKEND_URL")
        if env_url:
            backend_url = env_url.rstrip("/")

        if "THREATGUARD_HEARTBEAT_INTERVAL" in os.environ:
            try:
                heartbeat_interval = int(os.environ["THREATGUARD_HEARTBEAT_INTERVAL"])
            except ValueError:
                pass

        if "THREATGUARD_TIMEOUT" in os.environ:
            try:
                timeout = float(os.environ["THREATGUARD_TIMEOUT"])
            except ValueError:
                pass

        if "THREATGUARD_QUEUE_SIZE" in os.environ:
            try:
                queue_size = int(os.environ["THREATGUARD_QUEUE_SIZE"])
            except ValueError:
                pass

        if "THREATGUARD_AUTH_TOKEN" in os.environ:
            auth_token = os.environ["THREATGUARD_AUTH_TOKEN"]

        if "THREATGUARD_LOG_FILE" in os.environ:
            log_file = os.environ["THREATGUARD_LOG_FILE"]

        if "THREATGUARD_LOG_LEVEL" in os.environ:
            log_level = os.environ["THREATGUARD_LOG_LEVEL"].upper()

        return cls(
            backend_url=backend_url.rstrip("/"),
            heartbeat_interval=heartbeat_interval,
            timeout=timeout,
            queue_size=queue_size,
            auth_token=auth_token,
            log_file=log_file,
            log_level=log_level,
            device_id=device_id,
        )

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Construct config from config file and environment variables."""
        return cls.load()

    def save(self, destination: str | Path | None = None) -> Path:
        """Persist configuration to JSON file."""
        target_path = Path(destination) if destination else DEFAULT_SYSTEM_CONFIG_FILE
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "server_url": self.backend_url,
                "backend_url": self.backend_url,
                "heartbeat_interval": self.heartbeat_interval,
                "timeout": self.timeout,
                "queue_size": self.queue_size,
                "auth_token": self.auth_token,
                "log_file": self.log_file,
                "log_level": self.log_level,
                "device_id": self.device_id,
            }
            target_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            logger.info("Saved configuration to %s", target_path)
            return target_path
        except OSError as exc:
            # Fallback to user config if system directory is not writable
            fallback = DEFAULT_USER_CONFIG_FILE
            fallback.parent.mkdir(parents=True, exist_ok=True)
            fallback.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
            logger.warning("Could not write to %s (%s); saved to %s", target_path, exc, fallback)
            return fallback
