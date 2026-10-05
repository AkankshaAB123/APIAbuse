"""
Logging configuration for the ThreatGuard Windows Endpoint Agent.

Configures formatted console output and rotating file logging to
C:\\ProgramData\\ThreatGuard\\logs\\agent.log.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_agent_logging(
    log_file: str | Path | None = None,
    log_level: str = "INFO",
    *,
    console: bool = True,
) -> logging.Logger:
    """
    Configure root logger with console and rotating file handlers.

    Logs to C:\\ProgramData\\ThreatGuard\\logs\\agent.log by default.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Avoid duplicate handlers on re-entry
    if root_logger.handlers:
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 1. Console handler
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    # 2. File handler (C:\ProgramData\ThreatGuard\logs\agent.log)
    if log_file:
        file_path = Path(log_file)
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                str(file_path),
                maxBytes=5 * 1024 * 1024,  # 5 MB
                backupCount=3,
                encoding="utf-8",
            )
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except OSError as exc:
            logging.warning("Could not setup file logging at %s: %s", file_path, exc)

    return root_logger
