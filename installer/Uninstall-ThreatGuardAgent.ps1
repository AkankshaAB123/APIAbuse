# ==============================================================================
# ThreatGuard Windows Endpoint Agent Uninstaller Script
# ==============================================================================

[CmdletBinding()]
param (
    [string]$InstallDir = "C:\Program Files\ThreatGuard Agent",
    [string]$DataDir = "C:\ProgramData\ThreatGuard",
    [switch]$KeepLogs
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " ThreatGuard Windows Endpoint Agent - Uninstallation" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Administrator privileges required to uninstall Windows Services."
    Write-Host "Restarting script with elevated privileges..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit 0
}

Write-Host "[1/4] Stopping ThreatGuard Windows Service..." -ForegroundColor Green
$svc = Get-Service -Name "ThreatGuardAgent" -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") {
        & sc.exe stop ThreatGuardAgent | Out-Null
        Start-Sleep -Seconds 2
    }
    Write-Host "[2/4] Deleting ThreatGuard Windows Service..." -ForegroundColor Green
    & sc.exe delete ThreatGuardAgent | Out-Null
} else {
    Write-Host "  Service was not registered." -ForegroundColor Yellow
}

Write-Host "[3/4] Removing installed binaries from $InstallDir..." -ForegroundColor Green
if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
}

Write-Host "[4/4] Cleaning data files..." -ForegroundColor Green
if (-not $KeepLogs) {
    if (Test-Path $DataDir) {
        Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
        Write-Host "  Removed configuration and logs directory ($DataDir)."
    }
} else {
    Write-Host "  Preserved configuration and logs in $DataDir (as requested)." -ForegroundColor Yellow
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " ThreatGuard Agent Uninstalled Successfully." -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
