# ThreatGuard Windows Endpoint Agent

A lightweight Python agent that monitors Windows endpoint activity and
forwards security telemetry to the ThreatGuard backend for AI-powered
threat detection.

## Requirements

- Python 3.10+
- `requests` (already in project dependencies)
- ThreatGuard backend running (default: `http://127.0.0.1:8000`)

## Quick Start

```powershell
# From repo root — activate venv first
.\.venv\Scripts\Activate.ps1

# One-shot heartbeat
python -m agents.windows --once

# Send demo high-risk event
python -m agents.windows --demo

# Continuous monitoring (30-second heartbeat)
python -m agents.windows

# Custom backend
python -m agents.windows --backend-url http://192.168.1.10:8000 --once
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `THREATGUARD_BACKEND_URL` | `http://127.0.0.1:8000` | Backend base URL |
| `THREATGUARD_HEARTBEAT_INTERVAL` | `30` | Seconds between heartbeats |
| `THREATGUARD_TIMEOUT` | `8.0` | HTTP request timeout (seconds) |
| `THREATGUARD_QUEUE_SIZE` | `50` | Max events buffered when offline |
| `THREATGUARD_AUTH_TOKEN` | *(none)* | JWT token for authenticated endpoints |

## Module Structure

```
agents/windows/
├── __init__.py       — Package metadata
├── __main__.py       — Enables python -m agents.windows
├── config.py         — AgentConfig (env-based configuration)
├── device.py         — Stable hardware-derived device ID
├── telemetry.py      — ApiSecurityEvent payload builders
├── api_client.py     — HTTP client + offline event queue
├── notifier.py       — Console + Windows Toast alerts
├── monitor.py        — WindowsEndpointMonitor (main loop)
└── main.py           — argparse CLI
```

## Testing

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_windows_agent.py -v
```

## Design Notes

- **Device ID**: Derived from `platform.node() + machine + processor + MAC`
  via SHA-256, cached at `~/.threatguard/device_id`.
- **Offline queue**: Bounded `deque(maxlen=50)` — oldest events dropped when
  full. Queue flushed automatically on next successful backend connection.
- **Schema**: Posts `ApiSecurityEvent` with `domain="ENDPOINT"` and populated
  `endpoint` block. No separate schema — fully compatible with existing
  `POST /events` contract.
- **Notifications**: Console banner always; Windows Toast via PowerShell
  (best-effort, silently skipped on non-Windows or permission error).
