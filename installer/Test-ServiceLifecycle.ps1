# ==============================================================================
# ThreatGuard Agent - Full Service Lifecycle Test
# Must be run from an Administrator PowerShell.
# ==============================================================================
# Steps:
#   1. Stop and remove any existing service registration
#   2. Copy new EXE from dist\ to Program Files (the canonical install path)
#   3. Register service pointing to canonical path
#   4. Clear agent.log for a clean test
#   5. Start service
#   6. Confirm STATE = RUNNING at T+5s, T+30s, T+90s
#   7. Wait 90s total - confirm 3+ heartbeats in log
#   8. Stop service
#   9. Confirm STATE = STOPPED
#  10. Verify auto-start remains configured
# ==============================================================================

param(
    [string]$RepoRoot = (Join-Path $PSScriptRoot "..")
)

$ErrorActionPreference = "Stop"

$InstallDir  = "C:\Program Files\ThreatGuard Agent"
$InstallExe  = "$InstallDir\threatguard-agent.exe"
$DataDir     = "C:\ProgramData\ThreatGuard"
$LogFile     = "$DataDir\logs\agent.log"
$ServiceName = "ThreatGuardAgent"
$SrcExe      = Join-Path $RepoRoot "dist\threatguard-agent.exe"
$SrcExe      = (Resolve-Path $SrcExe).Path

# Verify admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator. Right-click PowerShell and select Run as Administrator."
    exit 1
}

function Sep  { Write-Host ("-" * 60) -ForegroundColor DarkGray }
function Head { param([string]$msg) Write-Host "" ; Write-Host "[$msg]" -ForegroundColor Cyan }
function OK   { param([string]$msg) Write-Host "  OK: $msg" -ForegroundColor Green }
function FAIL { param([string]$msg) Write-Host "  FAIL: $msg" -ForegroundColor Red }
function INFO { param([string]$msg) Write-Host "  $msg" -ForegroundColor White }

Head "STEP 1/10 - Stop and remove existing service"
Sep
& sc.exe stop $ServiceName 2>&1 | ForEach-Object { INFO "$_" }
Start-Sleep -Seconds 3
& sc.exe delete $ServiceName 2>&1 | ForEach-Object { INFO "$_" }
Start-Sleep -Seconds 2
OK "Old service removed (or was not present)"

Head "STEP 2/10 - Install EXE to canonical path"
Sep
INFO "Source : $SrcExe"
INFO "Dest   : $InstallExe"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Copy-Item -Path $SrcExe -Destination $InstallExe -Force
$installedSize = (Get-Item $InstallExe).Length
$installedDate = (Get-Item $InstallExe).LastWriteTime
OK "Installed: $installedSize bytes, written $installedDate"

Head "STEP 3/10 - Register Windows Service"
Sep
INFO "binPath: `"$InstallExe`" --service-run"
# sc.exe requires 'binPath= <value>' with space after '='.
# The value is: "C:\Program Files\ThreatGuard Agent\threatguard-agent.exe" --service-run
$scCmd = "sc.exe create $ServiceName binPath= `"\`"$InstallExe\`" --service-run`" start= auto DisplayName= `"ThreatGuard Endpoint Security Agent`""
INFO "Executing: $scCmd"
$createOutput = cmd.exe /c $scCmd 2>&1
$createExitCode = $LASTEXITCODE
$createOutput | ForEach-Object { INFO "$_" }
if ($createExitCode -ne 0) {
    FAIL "sc.exe create failed (exit $createExitCode)"
    exit 1
}
& sc.exe description $ServiceName "ThreatGuard endpoint security telemetry and monitoring agent service." | Out-Null
$scFailArgs = @(
    "failure",
    $ServiceName,
    "reset= 86400",
    "actions= restart/60000/restart/60000/restart/60000"
)
& sc.exe @scFailArgs | Out-Null
INFO "Service config after registration:"
& sc.exe qc $ServiceName
if ($LASTEXITCODE -eq 0) {
    OK "Service registered"
} else {
    FAIL "Service registration failed"
    exit 1
}

Head "STEP 4/10 - Clear agent.log"
Sep
if (-not (Test-Path "$DataDir\logs")) {
    New-Item -ItemType Directory -Path "$DataDir\logs" -Force | Out-Null
}
if (Test-Path $LogFile) {
    Clear-Content $LogFile
    OK "Cleared: $LogFile"
} else {
    OK "No existing log (fresh start)"
}

Head "STEP 5/10 - Start service"
Sep
$cleanName = $ServiceName.Trim()
INFO "Starting service: $cleanName"

$startArgs = @("start", $cleanName)
$startOutput = & sc.exe @startArgs 2>&1
$startExitCode = $LASTEXITCODE
$startOutput | ForEach-Object { INFO "$_" }

if ($startExitCode -ne 0) {
    INFO "Retrying service start via cmd.exe shell wrapper..."
    $startOutput = cmd.exe /c "sc.exe start $cleanName" 2>&1
    $startExitCode = $LASTEXITCODE
    $startOutput | ForEach-Object { INFO "$_" }
}

if ($startExitCode -ne 0) {
    INFO "Retrying service start via Start-Service cmdlet..."
    try {
        Start-Service -Name $cleanName -ErrorAction Stop
        $startExitCode = 0
        INFO "Start-Service cmdlet completed successfully."
    } catch {
        $startExitCode = 1
        INFO "Start-Service error: $($_.Exception.Message)"
    }
}

if ($startExitCode -eq 0) {
    $startTime = Get-Date
    OK "Service start initiated successfully at $startTime"
} else {
    FAIL "StartService failed (exit code $startExitCode). Aborting lifecycle test."
    exit 1
}

Head "STEP 6/10 - Confirm RUNNING at T+5s"
Sep
Start-Sleep -Seconds 5
$q = & sc.exe query $ServiceName
$q | ForEach-Object { INFO "$_" }
if ($q -match "RUNNING") {
    OK "Service is RUNNING at T+5s"
} else {
    FAIL "Service NOT RUNNING at T+5s - check $LogFile"
}

Head "STEP 6b/10 - Confirm still RUNNING at T+30s"
Sep
Start-Sleep -Seconds 25
$q = & sc.exe query $ServiceName
$q | ForEach-Object { INFO "$_" }
if ($q -match "RUNNING") {
    OK "Service is RUNNING at T+30s"
} else {
    FAIL "Service stopped before T+30s"
}

Head "STEP 6c/10 - Confirm still RUNNING at T+90s"
Sep
Start-Sleep -Seconds 60
$q = & sc.exe query $ServiceName
$q | ForEach-Object { INFO "$_" }
if ($q -match "RUNNING") {
    OK "Service is RUNNING at T+90s"
} else {
    FAIL "Service stopped before T+90s"
}

Head "STEP 7/10 - Verify heartbeats in log"
Sep
$logContent = Get-Content $LogFile -ErrorAction SilentlyContinue
$heartbeats  = $logContent | Where-Object { $_ -match "Heartbeat OK|HEARTBEAT" }
$logCount    = if ($logContent) { $logContent.Count } else { 0 }
$hbCount     = if ($heartbeats)  { $heartbeats.Count  } else { 0 }
INFO "Log entries found: $logCount"
INFO "Heartbeat entries: $hbCount"
if ($heartbeats) {
    $heartbeats | Select-Object -Last 5 | ForEach-Object { INFO "$_" }
}
if ($hbCount -ge 3) {
    OK "3+ heartbeats confirmed"
} else {
    FAIL "Fewer than 3 heartbeats found - service may not be working correctly"
}

Head "STEP 8/10 - Stop service"
Sep
$stopArgs = @("stop", $cleanName)
$stopOutput = & sc.exe @stopArgs 2>&1
$stopOutput | ForEach-Object { INFO "$_" }
Start-Sleep -Seconds 5
OK "Stop command issued"

Head "STEP 9/10 - Confirm STOPPED"
Sep
$q = & sc.exe query $ServiceName
$q | ForEach-Object { INFO "$_" }
if ($q -match "STOPPED") {
    OK "Service is STOPPED"
} else {
    FAIL "Service did not stop cleanly"
}

INFO "Final log tail (last 10 lines):"
$tail = Get-Content $LogFile -ErrorAction SilentlyContinue | Select-Object -Last 10
if ($tail) { $tail | ForEach-Object { INFO "  $_" } }

Head "STEP 10/10 - Verify AUTO_START configuration"
Sep
$qc = & sc.exe qc $ServiceName
$qc | ForEach-Object { INFO "$_" }
if ($qc -match "AUTO_START") {
    OK "AUTO_START is configured"
} else {
    FAIL "AUTO_START not set - check service configuration"
}

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host " Lifecycle test complete." -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host " Installed EXE : $InstallExe" -ForegroundColor White
Write-Host " Service name  : $ServiceName" -ForegroundColor White
Write-Host " Log file      : $LogFile" -ForegroundColor White
Write-Host ("=" * 60) -ForegroundColor Cyan
