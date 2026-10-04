"""
CLI entry point for the ThreatGuard Windows Endpoint Agent.

Usage examples
--------------
Run one heartbeat then exit::

    python -m agents.windows --once

Start continuous monitoring in console::

    python -m agents.windows

Send a high-risk demo event then exit::

    python -m agents.windows --demo

Service Management::

    python -m agents.windows --install-service
    python -m agents.windows --start-service
    python -m agents.windows --service-status
    python -m agents.windows --stop-service
    python -m agents.windows --uninstall-service

Custom backend URL::

    python -m agents.windows --backend-url http://192.168.1.10:8000 --once
"""
from __future__ import annotations

import argparse
import sys

from agents.windows.config import AgentConfig
from agents.windows.logging_config import setup_agent_logging
from agents.windows.monitor import WindowsEndpointMonitor
from agents.windows.service import (
    format_status_output,
    get_service_status,
    install_service,
    run_service_worker,
    start_service,
    stop_service,
    uninstall_service,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threatguard-windows-agent",
        description="ThreatGuard Windows Endpoint Security Agent",
    )
    p.add_argument(
        "--backend-url", "-b",
        default=None,
        metavar="URL",
        help="Override backend URL (default: config.json or http://127.0.0.1:8000)",
    )
    p.add_argument(
        "--interval", "-i",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Heartbeat interval in seconds (default: 30)",
    )
    p.add_argument(
        "--config", "-c",
        default=None,
        metavar="PATH",
        help="Path to custom config.json file",
    )
    p.add_argument(
        "--demo",
        action="store_true",
        help="Send a single synthetic high-risk event then exit",
    )
    p.add_argument(
        "--once",
        action="store_true",
        help="Send one heartbeat then exit (useful for CI / health checks)",
    )
    p.add_argument(
        "--status", "--service-status",
        dest="status",
        action="store_true",
        help="Display current service and telemetry status",
    )
    p.add_argument(
        "--install-service",
        action="store_true",
        help="Install agent as an automatic Windows Service",
    )
    p.add_argument(
        "--uninstall-service",
        action="store_true",
        help="Uninstall the Windows Service",
    )
    p.add_argument(
        "--start-service",
        action="store_true",
        help="Start the Windows Service",
    )
    p.add_argument(
        "--stop-service",
        action="store_true",
        help="Stop the Windows Service",
    )
    p.add_argument(
        "--service-run",
        action="store_true",
        help=argparse.SUPPRESS,  # Internal flag invoked by Service Control Manager
    )
    p.add_argument(
        "--no-toast",
        action="store_true",
        help="Disable Windows Toast notifications",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    """Parse CLI args and run the agent or service management command."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # 1. Service execution mode (invoked by Service Control Manager)
    if args.service_run:
        return run_service_worker(args.config)

    # 2. Service management commands
    if args.status:
        status = get_service_status()
        print(format_status_output(status))
        return 0

    if args.install_service:
        print("[ThreatGuard] Installing Windows Service ...")
        ok, msg = install_service(args.backend_url)
        print(f"  {'[OK]' if ok else '[FAIL]'} {msg}")
        return 0 if ok else 1

    if args.uninstall_service:
        print("[ThreatGuard] Uninstalling Windows Service ...")
        ok, msg = uninstall_service()
        print(f"  {'[OK]' if ok else '[FAIL]'} {msg}")
        return 0 if ok else 1

    if args.start_service:
        print("[ThreatGuard] Starting Windows Service ...")
        ok, msg = start_service()
        print(f"  {'[OK]' if ok else '[FAIL]'} {msg}")
        return 0 if ok else 1

    if args.stop_service:
        print("[ThreatGuard] Stopping Windows Service ...")
        ok, msg = stop_service()
        print(f"  {'[OK]' if ok else '[FAIL]'} {msg}")
        return 0 if ok else 1

    # 3. Interactive / CLI execution mode
    config = AgentConfig.load(args.config)
    if args.backend_url:
        config.backend_url = args.backend_url.rstrip("/")
    if args.interval is not None:
        config.heartbeat_interval = args.interval

    log_level = "DEBUG" if args.verbose else config.log_level
    setup_agent_logging(log_file=config.log_file, log_level=log_level, console=True)

    monitor = WindowsEndpointMonitor(config, toast_enabled=not args.no_toast)

    if args.demo:
        print("\n[ThreatGuard] Sending DEMO high-risk event ...")
        resp = monitor.send_demo_event()
        return 0 if resp.success else 1

    if args.once:
        print("\n[ThreatGuard] Sending single heartbeat ...")
        resp = monitor.send_heartbeat_once()
        return 0 if resp.success else 1

    # Continuous loop in console
    monitor.run_loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
