"""
CLI entry point for the ThreatGuard Windows Endpoint Agent.

Usage examples
--------------
Run one heartbeat then exit::

    python -m agents.windows --once

Start continuous monitoring::

    python -m agents.windows

Send a high-risk demo event then exit::

    python -m agents.windows --demo

Custom backend URL::

    python -m agents.windows --backend-url http://192.168.1.10:8000 --once
"""
from __future__ import annotations

import argparse
import logging
import sys

from agents.windows.config import AgentConfig
from agents.windows.monitor import WindowsEndpointMonitor


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threatguard-windows-agent",
        description="ThreatGuard Windows Endpoint Security Agent",
    )
    p.add_argument(
        "--backend-url", "-b",
        default=None,
        metavar="URL",
        help="Override backend URL (default: THREATGUARD_BACKEND_URL env or http://127.0.0.1:8000)",
    )
    p.add_argument(
        "--interval", "-i",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Heartbeat interval in seconds (default: 30)",
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
    """Parse CLI args and run the agent.  Returns exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        stream=sys.stdout,
    )

    # Build config — CLI flags override env vars
    config = AgentConfig.from_env()
    if args.backend_url:
        config.backend_url = args.backend_url.rstrip("/")
    if args.interval is not None:
        config.heartbeat_interval = args.interval

    monitor = WindowsEndpointMonitor(config, toast_enabled=not args.no_toast)

    if args.demo:
        print("\n[ThreatGuard] Sending DEMO high-risk event ...")
        resp = monitor.send_demo_event()
        return 0 if resp.success else 1

    if args.once:
        print("\n[ThreatGuard] Sending single heartbeat ...")
        resp = monitor.send_heartbeat_once()
        return 0 if resp.success else 1

    # Continuous loop
    monitor.run_loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
