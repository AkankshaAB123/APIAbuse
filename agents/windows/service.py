"""
Windows Service integration for the ThreatGuard Windows Endpoint Agent.

Provides:
1. Windows Service host for running the agent silently in the background
2. Service management commands (install, uninstall, start, stop, status)
3. Automatic failure recovery and restart configuration
4. Clean shutdown handling without visible console windows

Lifecycle
---------
When the Service Control Manager (SCM) launches the registered binary it calls
the entry point with ``--service-run``.  ``run_service_worker()`` then calls
``win32serviceutil.HandleCommandLine(ThreatGuardPywinService)`` which sets up
the proper SCM pipe, calls ``SvcDoRun``, and keeps the SCM heartbeat alive.

Without this delegation the SCM never receives ``SERVICE_RUNNING`` and kills
the process (exit code 0) after a startup timeout — which was the original bug.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any

from agents.windows.config import AgentConfig, DEFAULT_SYSTEM_CONFIG_FILE
from agents.windows.device import get_device_id
from agents.windows.logging_config import setup_agent_logging
from agents.windows.monitor import WindowsEndpointMonitor, SYSTEM_STATUS_FILE, USER_STATUS_FILE

logger = logging.getLogger(__name__)

SERVICE_NAME = "ThreatGuardAgent"
SERVICE_DISPLAY_NAME = "ThreatGuard Endpoint Security Agent"
SERVICE_DESCRIPTION = "ThreatGuard endpoint security telemetry and monitoring agent service."

# ---------------------------------------------------------------------------
# Canonical installation paths — single source of truth.
# These MUST match what Install-ThreatGuardAgent.ps1 and setup.iss use.
# All service registration (install_service, sc.exe create) must use INSTALL_EXE.
# ---------------------------------------------------------------------------
INSTALL_DIR = Path(r"C:\Program Files\ThreatGuard Agent")
INSTALL_EXE = INSTALL_DIR / "threatguard-agent.exe"

# Check if pywin32 is available
try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False


def _get_service_binary_command() -> str:
    """
    Return the binPath command used when registering the Windows Service.

    Always resolves to the canonical installed EXE path so that the service
    registration is consistent regardless of where the CLI is invoked from
    (Python source tree, packaged EXE, or a different directory).

    - When already running AS the installed frozen EXE (sys.executable matches
      INSTALL_EXE), use sys.executable directly so the path is exact.
    - In all other cases (running from source, dev box, CI) use INSTALL_EXE —
      the path the installer will have placed the binary at.

    This ensures sc.exe create always writes the same binPath value that
    Install-ThreatGuardAgent.ps1 and setup.iss write.
    """
    if getattr(sys, "frozen", False):
        # Running as PyInstaller frozen EXE — use the actual path of this
        # running executable (which IS the installed binary).
        exe_path = Path(sys.executable).resolve()
    else:
        # Running from Python source (dev/CI) — register the canonical path
        # that the installer will have deployed the EXE to.
        exe_path = INSTALL_EXE

    return f'"{exe_path}" --service-run'


# Keep the old name as an alias so existing tests / callers are not broken.
_get_agent_binary_command = _get_service_binary_command


def run_service_worker(config_path: str | Path | None = None) -> int:
    """
    Execute the agent monitor loop as a background service worker.

    When pywin32 is available this delegates to HandleCommandLine so the SCM
    receives proper SERVICE_RUNNING / SERVICE_STOPPED status updates.
    Falls back to a plain monitor loop when pywin32 is absent (non-Windows).
    """
    # ── Phase 1: bootstrap logging as early as possible ──────────────────────
    try:
        config = AgentConfig.load(config_path)
        device_id = get_device_id()
        config.device_id = device_id
        setup_agent_logging(
            log_file=config.log_file,
            log_level=config.log_level,
            console=False,
        )
    except Exception:  # noqa: BLE001
        # Logging setup failed — write raw traceback to a fallback file
        _fallback_log = (
            Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
            / "ThreatGuard" / "logs" / "bootstrap_error.log"
        )
        try:
            _fallback_log.parent.mkdir(parents=True, exist_ok=True)
            _fallback_log.write_text(traceback.format_exc(), encoding="utf-8")
        except Exception:
            pass
        return 2

    logger.info("=" * 60)
    logger.info(
        "[SERVICE-ENTRY] --service-run received  PID=%s  frozen=%s",
        os.getpid(), getattr(sys, "frozen", False),
    )
    logger.info("[SERVICE-ENTRY] PYWIN32_AVAILABLE=%s", PYWIN32_AVAILABLE)
    logger.info("ThreatGuard Agent Service starting")
    logger.info("Service Name : %s", SERVICE_NAME)
    logger.info("Device ID    : %s", device_id)
    logger.info("Server URL   : %s", config.backend_url)
    logger.info("Interval     : %ds", config.heartbeat_interval)
    logger.info("Log File     : %s", config.log_file)
    logger.info("=" * 60)

    # ── Phase 2: delegate to pywin32 Service Control Manager dispatcher ─────
    if PYWIN32_AVAILABLE:
        logger.info(
            "[SERVICE-FRAMEWORK] Connecting to Service Control Manager dispatcher"
        )
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(ThreatGuardPywinService)
            # StartServiceCtrlDispatcher blocks until SCM sends stop and SvcDoRun exits
            servicemanager.StartServiceCtrlDispatcher()
            logger.info(
                "[SERVICE-FRAMEWORK] StartServiceCtrlDispatcher returned normally — "
                "service lifecycle complete."
            )
            return 0
        except Exception as exc:
            # If run interactively from terminal without SCM, winerror 1063 is raised
            if getattr(exc, "winerror", None) == 1063:
                logger.warning(
                    "[SERVICE-FRAMEWORK] Not running under SCM (error 1063) — "
                    "running console monitor loop."
                )
                monitor = WindowsEndpointMonitor(config, toast_enabled=False)
                monitor.run_loop()
                return 0
            logger.exception(
                "[SERVICE-FRAMEWORK] StartServiceCtrlDispatcher raised unhandled exception:\n%s",
                traceback.format_exc(),
            )
            return 1

    # ── Phase 3: fallback plain loop (no pywin32 — non-Windows CI, etc.) ─────
    logger.warning(
        "[SERVICE-FALLBACK] pywin32 not available — running plain monitor loop "
        "(no SCM integration; service will not stay RUNNING in Windows SCM)"
    )
    monitor = WindowsEndpointMonitor(config, toast_enabled=False)
    try:
        logger.info("[MONITOR-START] Calling monitor.run_loop()")
        monitor.run_loop()
        logger.info("[MONITOR-RETURN] monitor.run_loop() returned normally.")
    except Exception:
        logger.exception(
            "[MONITOR-EXCEPTION] Unhandled exception in monitor.run_loop():\n%s",
            traceback.format_exc(),
        )
        return 1
    finally:
        logger.info(
            "[SERVICE-STOPPED] ThreatGuard Agent Service stopped cleanly "
            "(fallback path)."
        )

    return 0


def install_service(backend_url: str | None = None) -> tuple[bool, str]:
    """
    Install the agent as an automatic Windows Service using sc.exe.

    Configures auto-start and automatic recovery on failure.
    """
    if backend_url:
        cfg = AgentConfig.load()
        cfg.backend_url = backend_url.rstrip("/")
        cfg.save()

    bin_path = _get_agent_binary_command()

    # 1. Create the service
    create_cmd = [
        "sc.exe", "create", SERVICE_NAME,
        f"binPath= {bin_path}",
        "start= auto",
        f"DisplayName= {SERVICE_DISPLAY_NAME}",
    ]
    res = subprocess.run(create_cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0 and "already exists" not in res.stderr.lower() and "already exists" not in res.stdout.lower():
        return False, f"Failed to create service: {res.stdout.strip()} {res.stderr.strip()}"

    # 2. Set service description
    desc_cmd = ["sc.exe", "description", SERVICE_NAME, SERVICE_DESCRIPTION]
    subprocess.run(desc_cmd, capture_output=True, text=True, check=False)

    # 3. Configure recovery actions (restart after 60s on crash, reset count after 1 day)
    recovery_cmd = [
        "sc.exe", "failure", SERVICE_NAME,
        "reset= 86400",
        "actions= restart/60000/restart/60000/restart/60000",
    ]
    subprocess.run(recovery_cmd, capture_output=True, text=True, check=False)

    return True, f"Service '{SERVICE_NAME}' installed successfully with automatic startup."


def uninstall_service() -> tuple[bool, str]:
    """Stop and delete the ThreatGuard Windows Service."""
    # Attempt stop first
    subprocess.run(["sc.exe", "stop", SERVICE_NAME], capture_output=True, text=True, check=False)

    # Delete service
    res = subprocess.run(["sc.exe", "delete", SERVICE_NAME], capture_output=True, text=True, check=False)
    if res.returncode != 0:
        return False, f"Failed to delete service: {res.stdout.strip()} {res.stderr.strip()}"

    return True, f"Service '{SERVICE_NAME}' uninstalled successfully."


def start_service() -> tuple[bool, str]:
    """Start the ThreatGuard Windows Service."""
    res = subprocess.run(["sc.exe", "start", SERVICE_NAME], capture_output=True, text=True, check=False)
    out = (res.stdout + res.stderr).strip()
    if res.returncode != 0 and "already running" not in out.lower() and "running" not in out.lower():
        return False, f"Failed to start service: {out}"
    return True, f"Service '{SERVICE_NAME}' started successfully."


def stop_service() -> tuple[bool, str]:
    """Stop the ThreatGuard Windows Service."""
    res = subprocess.run(["sc.exe", "stop", SERVICE_NAME], capture_output=True, text=True, check=False)
    out = (res.stdout + res.stderr).strip()
    if res.returncode != 0 and "not started" not in out.lower() and "stopped" not in out.lower():
        return False, f"Failed to stop service: {out}"
    return True, f"Service '{SERVICE_NAME}' stopped successfully."


def get_service_status() -> dict[str, Any]:
    """Query current Windows Service state and runtime telemetry status."""
    service_state = "NOT_INSTALLED"
    res = subprocess.run(["sc.exe", "query", SERVICE_NAME], capture_output=True, text=True, check=False)
    output = res.stdout.upper()

    if "STATE" in output:
        if "RUNNING" in output:
            service_state = "RUNNING"
        elif "STOPPED" in output:
            service_state = "STOPPED"
        elif "START_PENDING" in output:
            service_state = "START_PENDING"
        elif "STOP_PENDING" in output:
            service_state = "STOP_PENDING"
        else:
            service_state = "INSTALLED"

    # Read runtime status file if available
    runtime_data: dict[str, Any] = {}
    for path in (SYSTEM_STATUS_FILE, USER_STATUS_FILE):
        try:
            if path.exists():
                parsed = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    runtime_data = parsed
                    break
        except Exception:
            continue

    cfg = AgentConfig.load()
    device_id = get_device_id()

    return {
        "service_name": SERVICE_NAME,
        "service_state": service_state,
        "device_id": runtime_data.get("device_id") or device_id,
        "server_url": runtime_data.get("server_url") or cfg.backend_url,
        "last_heartbeat": runtime_data.get("updated_at", "Never"),
        "last_event_type": runtime_data.get("last_event_type", "None"),
        "last_mitigation": runtime_data.get("last_mitigation", "None"),
        "queue_size": runtime_data.get("queue_size", 0),
        "log_file": cfg.log_file,
    }


def format_status_output(status: dict[str, Any]) -> str:
    """Format the status dictionary for clean CLI display."""
    lines = [
        "",
        "=" * 50,
        "  ThreatGuard Windows Endpoint Agent",
        "=" * 50,
        f"  Service Status : {status.get('service_state')}",
        f"  Device ID      : {status.get('device_id')}",
        f"  Server URL     : {status.get('server_url')}",
        f"  Last Activity  : {status.get('last_heartbeat')}",
        f"  Last Event     : {status.get('last_event_type')}",
        f"  Last Decision  : {status.get('last_mitigation')}",
        f"  Offline Queue  : {status.get('queue_size')} events",
        f"  Log File       : {status.get('log_file')}",
        "=" * 50,
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Native pywin32 Service Framework implementation (when available)
# ---------------------------------------------------------------------------
if PYWIN32_AVAILABLE:
    class ThreatGuardPywinService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.monitor: WindowsEndpointMonitor | None = None
            logger.info(
                "[PYWIN32-INIT] ThreatGuardPywinService.__init__ called  args=%s",
                args,
            )

        def SvcStop(self):
            """Called by SCM to request service shutdown."""
            logger.info(
                "[PYWIN32-STOP] SvcStop received from Service Control Manager."
            )
            try:
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                logger.info(
                    "[PYWIN32-STOP] Reported SERVICE_STOP_PENDING to SCM."
                )
                if self.monitor:
                    self.monitor.stop()
                    logger.info(
                        "[PYWIN32-STOP] monitor.stop() called — loop will exit "
                        "within next heartbeat interval."
                    )
                win32event.SetEvent(self.hWaitStop)
                logger.info("[PYWIN32-STOP] hWaitStop event signalled.")
            except Exception:
                logger.exception(
                    "[PYWIN32-STOP] Exception in SvcStop:\n%s",
                    traceback.format_exc(),
                )

        def SvcDoRun(self):
            """Main service body — called by HandleCommandLine after SCM registration."""
            logger.info("[PYWIN32-DORUN] SvcDoRun entered.")
            try:
                config = AgentConfig.load()
                setup_agent_logging(
                    log_file=config.log_file,
                    log_level=config.log_level,
                    console=False,
                )
                logger.info(
                    "[PYWIN32-DORUN] Config loaded — reporting SERVICE_RUNNING to SCM."
                )
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                logger.info(
                    "[PYWIN32-DORUN] SERVICE_RUNNING reported — starting monitor loop."
                )
                self.monitor = WindowsEndpointMonitor(config, toast_enabled=False)
                logger.info("[MONITOR-START] monitor.run_loop() starting")
                self.monitor.run_loop()
                logger.info("[MONITOR-RETURN] monitor.run_loop() returned normally.")
            except Exception:
                logger.exception(
                    "[PYWIN32-DORUN] Unhandled exception in SvcDoRun:\n%s",
                    traceback.format_exc(),
                )
            finally:
                logger.info(
                    "[PYWIN32-DORUN] SvcDoRun exiting — service will transition "
                    "to SERVICE_STOPPED."
                )
