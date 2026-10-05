# ThreatGuard Windows Endpoint Security Agent

A production-grade, installable Windows security telemetry and monitoring agent that observes endpoint events, forwards telemetry to the centralized ThreatGuard IDS backend, and issues real-time threat notifications.

---

## Product Scope & Enforcement Distinction (Important)

> [!IMPORTANT]
> **Scope & Capabilities**: The ThreatGuard Windows Agent is an **Endpoint Security Monitoring and Telemetry Agent**, NOT a kernel-level Antivirus or EDR driver.
> 
> * **What IS Genuinely Performed**:
>   - Collects deterministic endpoint hardware identity and system telemetry
>   - Submits structured endpoint events to ThreatGuard `/events`
>   - Buffers events in an in-memory bounded offline queue during backend outages
>   - Runs silently in the background as an automatic Windows Service (`ThreatGuardAgent`) with failure restart recovery
>   - Receives risk scoring and mitigation recommendations (`QUARANTINE`, `BLOCK`, `RATE_LIMIT`, `ALLOW`)
>   - Logs mitigation decisions and displays desktop alerts / Windows Toast notifications.
> * **What IS NOT Performed**:
>   - The agent does **NOT** kill arbitrary OS processes or isolate kernel drivers unless specific OS-level hooks are configured.
>   - It must **NOT** be represented as a full antivirus or malware scanner.

---

## Architecture Overview

```
                      +---------------------------------------+
                      | ThreatGuard Server (:8000 / :8080)     |
                      |   - /events  (API / Endpoint IDS)      |
                      |   - Rule Detectors + Risk Engine       |
                      +---------------------------------------+
                                          ▲
                           HTTP POST /events (ApiSecurityEvent)
                           JSON Response (ProcessingResult)
                                          │
                      +---------------------------------------+
                      | Windows Endpoint Agent Service        |
                      |   - Service Name: ThreatGuardAgent    |
                      |   - Config: ProgramData\config.json   |
                      |   - Logs: ProgramData\logs\agent.log  |
                      |   - Auto-Recovery on crash            |
                      +---------------------------------------+
                             │                       │
                     (Telemetry Engine)       (Offline Queue)
                     - Heartbeat (30s)        - Bounded deque
                     - Device ID (SHA-256)    - Auto-flush
                     - Synthetic Demo         - Drop oldest
```

---

## Component Layout

```
agents/windows/
├── __init__.py        — Package metadata
├── __main__.py        — Enables `python -m agents.windows`
├── config.py          — AgentConfig (layered JSON, env, and CLI configuration)
├── device.py          — Stable hardware-derived device ID
├── telemetry.py       — ApiSecurityEvent payload builders (domain="ENDPOINT")
├── api_client.py      — HTTP client + bounded offline replay queue
├── notifier.py        — Console alerts + Windows Toast notifications
├── monitor.py         — WindowsEndpointMonitor (main loop & status tracking)
├── logging_config.py  — Rotating file logging (C:\ProgramData\ThreatGuard\logs\agent.log)
├── service.py         — Windows Service implementation & management (sc.exe / pywin32)
├── main.py            — Unified CLI entry point
└── README.md          — Documentation
```

---

## 1. Development Mode (Python Environment)

From the project root with the virtual environment activated:

```powershell
# Send a single heartbeat and exit (health check)
python -m agents.windows --once

# Send a synthetic high-risk demo threat event (simulated reverse shell)
python -m agents.windows --demo

# Check agent service status and telemetry stats
python -m agents.windows --status

# Continuous monitoring loop in console
python -m agents.windows

# Custom backend URL and heartbeat interval
python -m agents.windows --backend-url http://192.168.1.100:8000 --interval 15
```

---

## 2. Windows Service Management Commands

The agent includes built-in service management commands:

```powershell
# Install as an automatic Windows Service (requires Administrator)
python -m agents.windows --install-service [--backend-url http://SERVER:8000]

# Start the service
python -m agents.windows --start-service

# Query service status and live telemetry
python -m agents.windows --status

# Stop the service
python -m agents.windows --stop-service

# Uninstall the service
python -m agents.windows --uninstall-service
```

---

## 3. Standalone Packaging (No Python Required)

The agent can be compiled into a single standalone executable that runs without Python, Git, or VS Code on any Windows target:

```powershell
# Compile dist\threatguard-agent.exe using PyInstaller
powershell -ExecutionPolicy Bypass -File installer\build_agent.ps1

# Assemble full deployment bundle in dist\ThreatGuard-Agent-Setup\
powershell -ExecutionPolicy Bypass -File installer\build_installer.ps1
```

The resulting `dist\threatguard-agent.exe` is ~16 MB and completely self-contained.

---

## 4. Production Installation Workflow

For client laptops without developer tools:

1. Copy the `dist\ThreatGuard-Agent-Setup\` folder to the client machine.
2. Right-click **`Setup.bat`** and select **Run as Administrator**.
3. The installer:
   - Installs files to `C:\Program Files\ThreatGuard Agent\`
   - Creates `C:\ProgramData\ThreatGuard\` configuration and `logs\`
   - Registers Windows Service `ThreatGuardAgent` with startup type `Automatic`
   - Configures automatic crash recovery (restarts automatically after 60s)
   - Starts the service silently in the background.

To install silently with a custom server URL via PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File .\Install-ThreatGuardAgent.ps1 -ServerUrl "http://192.168.1.50:8000"
```

---

## 5. Configuration & Storage Locations

Configuration is loaded in priority order:
1. CLI arguments (`--backend-url`, `--interval`, etc.)
2. Environment variables (`THREATGUARD_SERVER_URL` or `THREATGUARD_BACKEND_URL`)
3. Machine-wide configuration file: **`C:\ProgramData\ThreatGuard\config.json`**
4. User-profile fallback: `~/.threatguard/config.json`
5. Default settings: `http://127.0.0.1:8000`, 30s interval.

### Sample `C:\ProgramData\ThreatGuard\config.json`
```json
{
  "server_url": "http://127.0.0.1:8000",
  "backend_url": "http://127.0.0.1:8000",
  "heartbeat_interval": 30,
  "timeout": 8.0,
  "queue_size": 50,
  "auth_token": null,
  "log_file": "C:\\ProgramData\\ThreatGuard\\logs\\agent.log",
  "log_level": "INFO",
  "device_id": "WIN-69B8BDCC69F30CB1"
}
```

---

## 6. Logging & Offline Resilience

* **Log File**: `C:\ProgramData\ThreatGuard\logs\agent.log`
  - Uses a rotating file handler (5 MB max, 3 backup files).
  - Logs service startup, backend URL, device ID, successful heartbeats, network disconnects, and mitigation decisions.
  - Does **NOT** log tokens or sensitive data.
* **Offline Queue**:
  - If the ThreatGuard server is temporarily unreachable, events are stored in a bounded FIFO queue (`maxlen=50`).
  - When connection is restored, buffered events are automatically flushed in order.

---

## 7. Uninstallation

To cleanly remove the agent:
* Run **`Uninstall.bat`** as Administrator, or:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\Uninstall-ThreatGuardAgent.ps1
  ```
* Stops and deletes the `ThreatGuardAgent` Windows Service.
* Removes files from `C:\Program Files\ThreatGuard Agent\`.

---

## 8. Verification & Testing

Run all agent unit tests (including configuration persistence, service commands, and offline queue):
```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_windows_agent.py tests/test_windows_agent_service.py -v
```
