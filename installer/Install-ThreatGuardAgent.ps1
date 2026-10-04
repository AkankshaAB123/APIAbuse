# ==============================================================================
# ThreatGuard Windows Endpoint Agent Installer Script
# ==============================================================================
# Usage:
#   .\Install-ThreatGuardAgent.ps1 [-ServerUrl "http://192.168.1.100:8000"]
# ==============================================================================

[CmdletBinding()]
param (
    [string]$ServerUrl = "http://127.0.0.1:8000",
    [string]$InstallDir = "C:\Program Files\ThreatGuard Agent",
    [string]$DataDir = "C:\ProgramData\ThreatGuard",
    [switch]$Interactive
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " ThreatGuard Windows Endpoint Agent - Installation" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Administrator privileges required to install Windows Services."
    Write-Host "Restarting script with elevated privileges..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ServerUrl `"$ServerUrl`""
    exit 0
}

# Prompt for Server URL in interactive mode
if ($Interactive) {
    $prompt = Read-Host "Enter ThreatGuard Server URL [default: $ServerUrl]"
    if (-not [string]::IsNullOrWhiteSpace($prompt)) {
        $ServerUrl = $prompt.Trim().TrimEnd("/")
    }
}

Write-Host "[1/6] Setting up directories..." -ForegroundColor Green
$null = New-Item -ItemType Directory -Force -Path $InstallDir
$null = New-Item -ItemType Directory -Force -Path $DataDir
$null = New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "logs")

# Locate source binary
$SourceExe = $null
$CandidatePaths = @(
    (Join-Path $PSScriptRoot "threatguard-agent.exe"),
    (Join-Path $PSScriptRoot "..\dist\threatguard-agent.exe"),
    (Join-Path (Get-Location) "dist\threatguard-agent.exe")
)

foreach ($candidate in $CandidatePaths) {
    if (Test-Path $candidate) {
        $SourceExe = (Resolve-Path $candidate).Path
        break
    }
}

if (-not $SourceExe) {
    Write-Error "Could not find 'threatguard-agent.exe'. Please run 'build_agent.ps1' first or place the executable in the installer directory."
    exit 1
}

Write-Host "[2/6] Installing executable to $InstallDir..." -ForegroundColor Green
$DestExe = Join-Path $InstallDir "threatguard-agent.exe"

# Stop existing service if running before overwriting binary
$svc = Get-Service -Name "ThreatGuardAgent" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "  Stopping existing service..." -ForegroundColor Yellow
    Stop-Service -Name "ThreatGuardAgent" -Force
    Start-Sleep -Seconds 2
}

Copy-Item -Path $SourceExe -Destination $DestExe -Force

Write-Host "[3/6] Generating initial configuration in $DataDir..." -ForegroundColor Green
$ConfigFile = Join-Path $DataDir "config.json"
$ConfigData = @{
    server_url = $ServerUrl
    backend_url = $ServerUrl
    heartbeat_interval = 30
    timeout = 8.0
    queue_size = 50
    auth_token = $null
    log_file = (Join-Path $DataDir "logs\agent.log")
    log_level = "INFO"
    device_id = $null
}

# Preserve existing device_id if already present
$DeviceFile = Join-Path $DataDir "device_id"
if (Test-Path $DeviceFile) {
    $existingDevId = (Get-Content $DeviceFile -Raw).Trim()
    if ($existingDevId) {
        $ConfigData["device_id"] = $existingDevId
    }
}

$ConfigData | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigFile -Encoding UTF8

Write-Host "[4/6] Registering ThreatGuard Windows Service..." -ForegroundColor Green
$BinPathWithArgs = "`"$DestExe`" --service-run"

# Remove old service if exists
if (Get-Service -Name "ThreatGuardAgent" -ErrorAction SilentlyContinue) {
    & sc.exe stop ThreatGuardAgent | Out-Null
    & sc.exe delete ThreatGuardAgent | Out-Null
    Start-Sleep -Seconds 1
}

# Create new automatic service
# sc.exe requires 'binPath= <value>' with space after '='.
# The value is: "C:\Program Files\ThreatGuard Agent\threatguard-agent.exe" --service-run
$scCmd = "sc.exe create ThreatGuardAgent binPath= `"\`"$DestExe\`" --service-run`" start= auto DisplayName= `"ThreatGuard Endpoint Security Agent`""
$createOutput = cmd.exe /c $scCmd 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create service: $createOutput"
    exit 1
}
& sc.exe description ThreatGuardAgent "ThreatGuard endpoint security telemetry and monitoring agent service." | Out-Null
# Configure auto-restart on failure (60s delay, reset fail counter after 1 day)
& sc.exe failure ThreatGuardAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

Write-Host "[5/6] Starting ThreatGuard Agent Service..." -ForegroundColor Green
& sc.exe start ThreatGuardAgent
Start-Sleep -Seconds 2

Write-Host "[6/6] Checking Service Status..." -ForegroundColor Green
& $DestExe --status

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " ThreatGuard Agent Installed and Started Successfully!" -ForegroundColor Cyan
Write-Host " Binary : $DestExe" -ForegroundColor Cyan
Write-Host " Config : $ConfigFile" -ForegroundColor Cyan
Write-Host " Logs   : $(Join-Path $DataDir 'logs\agent.log')" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
