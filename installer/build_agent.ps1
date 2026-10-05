# ==============================================================================
# Build Standalone ThreatGuard Windows Endpoint Agent Executable
# ==============================================================================
# Requires: PyInstaller (pip install pyinstaller)
# Output  : dist/threatguard-agent.exe
# ==============================================================================

[CmdletBinding()]
param (
    [string]$PythonExe = ".\.venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Building ThreatGuard Windows Agent Standalone Binary..." -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Verify Python environment
if (-not (Test-Path $PythonExe)) {
    Write-Warning "Python environment not found at $PythonExe. Falling back to system python."
    $PythonExe = "python"
}

# Run PyInstaller
Write-Host "[1/3] Compiling standalone agent binary using PyInstaller..." -ForegroundColor Green
& $PythonExe -m PyInstaller --clean --noconfirm installer/threatguard_agent.spec

$OutputExe = ".\dist\threatguard-agent.exe"
if (-not (Test-Path $OutputExe)) {
    Write-Error "Build failed: $OutputExe was not generated."
    exit 1
}

$SizeMB = [math]::Round(((Get-Item $OutputExe).Length / 1MB), 2)
Write-Host "[2/3] Standalone binary generated successfully: $OutputExe ($SizeMB MB)" -ForegroundColor Green

# Test the generated binary
Write-Host "[3/3] Verifying standalone executable with --status ..." -ForegroundColor Green
& $OutputExe --status

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Standalone Agent Build Complete!" -ForegroundColor Cyan
Write-Host " Executable: $OutputExe" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
