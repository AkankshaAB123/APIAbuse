# ThreatGuard Windows Endpoint Agent Installer

This directory contains the packaging and installation toolchain for compiling the ThreatGuard Windows Endpoint Agent into a standalone binary and installing it as an automatic Windows Service.

---

## Directory Contents

| File | Purpose |
|---|---|
| `threatguard_agent.spec` | PyInstaller specification file for compiling `dist\threatguard-agent.exe`. Excludes heavy ML/PyTorch dependencies to keep binary size under 16 MB. |
| `build_agent.ps1` | Compiles the standalone executable using PyInstaller. |
| `build_installer.ps1` | End-to-end build script: compiles standalone binary, bundles deployment package into `dist\ThreatGuard-Agent-Setup\`, and invokes Inno Setup (`iscc.exe`) if available. |
| `Install-ThreatGuardAgent.ps1` | PowerShell installer script for deploying files to `C:\Program Files\ThreatGuard Agent`, configuring `C:\ProgramData\ThreatGuard`, and registering the auto-starting Windows Service. |
| `Uninstall-ThreatGuardAgent.ps1` | Clean uninstaller script: stops and deletes Windows Service, cleans up installation directories. |
| `setup.iss` | Inno Setup compiler script for building `ThreatGuard-Agent-Setup.exe` installer wizard. |
| `config.template.json` | Default configuration template deployed to `C:\ProgramData\ThreatGuard\config.json`. |

---

## Prerequisites

1. **Python 3.12+** with virtual environment:
   ```powershell
   .venv\Scripts\python.exe -m pip install pyinstaller pywin32
   ```
2. **Inno Setup 6** (Optional, for building single `ThreatGuard-Agent-Setup.exe` wizard):
   - Download: https://jrsoftware.org/isinfo.php
   - If Inno Setup is not installed, the PowerShell installer bundle in `dist\ThreatGuard-Agent-Setup\` is used.

---

## How to Build

### 1. Build Standalone Agent Binary

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File installer\build_agent.ps1
```
*Output*: `dist\threatguard-agent.exe` (~16 MB)

### 2. Build Complete Installer / Deployment Bundle

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File installer\build_installer.ps1
```
*Outputs*:
- `dist\ThreatGuard-Agent-Setup\` (Self-contained portable deployment folder with `Setup.bat`)
- `dist\ThreatGuard-Agent-Setup.exe` (Single-file GUI installer if Inno Setup is present)

---

## Deployment on Target Windows Machine

The target machine does **NOT** require Python, pip, VS Code, or a Git repository.

### Option A: One-Click Setup (Recommended)
1. Copy `dist\ThreatGuard-Agent-Setup\` to the target laptop (e.g. via USB or network share).
2. Right-click `Setup.bat` and select **Run as Administrator**.
3. The installer:
   - Installs executable to `C:\Program Files\ThreatGuard Agent\threatguard-agent.exe`
   - Configures settings at `C:\ProgramData\ThreatGuard\config.json`
   - Creates log file at `C:\ProgramData\ThreatGuard\logs\agent.log`
   - Registers Windows Service `ThreatGuardAgent`
   - Sets startup type to `Automatic` with crash recovery
   - Starts the service immediately.

### Option B: Silent / Scripted Installation with Custom Server URL
```powershell
powershell -ExecutionPolicy Bypass -File .\Install-ThreatGuardAgent.ps1 -ServerUrl "http://192.168.1.100:8000"
```

---

## Service Management & Verification

Once installed, manage the agent using `threatguard-agent.exe` or standard Windows tools:

```powershell
# Check live agent status and telemetry stats
& "C:\Program Files\ThreatGuard Agent\threatguard-agent.exe" --status

# Windows Service Control commands
sc.exe query ThreatGuardAgent
sc.exe stop ThreatGuardAgent
sc.exe start ThreatGuardAgent

# View live log file
Get-Content -Wait "C:\ProgramData\ThreatGuard\logs\agent.log"
```

---

## Uninstallation

Run `Uninstall.bat` as Administrator, or:
```powershell
powershell -ExecutionPolicy Bypass -File .\Uninstall-ThreatGuardAgent.ps1
```
