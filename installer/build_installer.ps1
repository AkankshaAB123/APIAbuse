# ==============================================================================
# Build Complete ThreatGuard Agent Installer
# ==============================================================================
# 1. Compiles standalone binary (dist/threatguard-agent.exe) via PyInstaller
# 2. Bundles portable deployment package in dist/ThreatGuard-Agent-Setup/
# 3. If Inno Setup (iscc.exe) is available, compiles ThreatGuard-Agent-Setup.exe
# ==============================================================================

[CmdletBinding()]
param (
    [string]$PythonExe = ".\.venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Building ThreatGuard Agent Distribution Package..." -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Step 1: Build standalone binary
Write-Host "`n[Step 1/3] Building standalone executable..." -ForegroundColor Green
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build_agent.ps1") -PythonExe $PythonExe

$AgentExe = Join-Path (Get-Location) "dist\threatguard-agent.exe"
if (-not (Test-Path $AgentExe)) {
    Write-Error "Binary build failed: $AgentExe was not found."
    exit 1
}

# Step 2: Assemble distribution folder
Write-Host "`n[Step 2/3] Assembling deployment bundle..." -ForegroundColor Green
$DistFolder = Join-Path (Get-Location) "dist\ThreatGuard-Agent-Setup"
$null = New-Item -ItemType Directory -Force -Path $DistFolder

Copy-Item -Path $AgentExe -Destination $DistFolder -Force
Copy-Item -Path (Join-Path $PSScriptRoot "Install-ThreatGuardAgent.ps1") -Destination $DistFolder -Force
Copy-Item -Path (Join-Path $PSScriptRoot "Uninstall-ThreatGuardAgent.ps1") -Destination $DistFolder -Force
Copy-Item -Path (Join-Path $PSScriptRoot "config.template.json") -Destination $DistFolder -Force

# Create convenient one-click Setup.bat
$SetupBat = Join-Path $DistFolder "Setup.bat"
@"
@echo off
echo Starting ThreatGuard Agent Installation...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0Install-ThreatGuardAgent.ps1""' }"
"@ | Set-Content -Path $SetupBat -Encoding ASCII

# Create convenient one-click Uninstall.bat
$UninstallBat = Join-Path $DistFolder "Uninstall.bat"
@"
@echo off
echo Starting ThreatGuard Agent Uninstallation...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0Uninstall-ThreatGuardAgent.ps1""' }"
"@ | Set-Content -Path $UninstallBat -Encoding ASCII

Write-Host "  Deployment folder assembled at: $DistFolder" -ForegroundColor Green

# Step 3: Check for Inno Setup compiler to create ThreatGuard-Agent-Setup.exe
Write-Host "`n[Step 3/3] Checking for Inno Setup compiler (iscc.exe)..." -ForegroundColor Green
$iscc = Get-Command "iscc.exe" -ErrorAction SilentlyContinue
$commonIsccPaths = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
)

if (-not $iscc) {
    foreach ($candidate in $commonIsccPaths) {
        if (Test-Path $candidate) {
            $iscc = $candidate
            break
        }
    }
}

if ($iscc) {
    Write-Host "  Inno Setup detected: $iscc" -ForegroundColor Green
    Write-Host "  Compiling ThreatGuard-Agent-Setup.exe ..." -ForegroundColor Green
    & $iscc (Join-Path $PSScriptRoot "setup.iss")
    Write-Host "  Compiled installer created: dist\ThreatGuard-Agent-Setup.exe" -ForegroundColor Green
} else {
    Write-Host "  Inno Setup (ISCC.exe) not found on system path." -ForegroundColor Yellow
    Write-Host "  A complete portable installer bundle has been generated in:" -ForegroundColor Green
    Write-Host "    $DistFolder" -ForegroundColor Cyan
    Write-Host "  To install on any Windows target without Python/Git, run:" -ForegroundColor Yellow
    Write-Host "    $DistFolder\Setup.bat" -ForegroundColor Cyan
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host " Build Process Finished Successfully!" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
