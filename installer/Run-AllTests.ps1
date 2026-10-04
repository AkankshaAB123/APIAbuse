# ==============================================================================
# Run-AllTests.ps1
# Run from Administrator PowerShell.
# 1. Runs Verify-RegistrationFix.ps1 (registration + start + query)
# 2. On success, runs Test-ServiceLifecycle.ps1 (full lifecycle)
# ==============================================================================
$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Must be run as Administrator."
    exit 1
}

$ScriptDir = $PSScriptRoot

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host " PHASE 1: Registration Fix Verification" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
& "$ScriptDir\Verify-RegistrationFix.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "PHASE 1 FAILED - aborting lifecycle test." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host " PHASE 2: Full Lifecycle Test" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
& "$ScriptDir\Test-ServiceLifecycle.ps1"
