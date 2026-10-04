# ==============================================================================
# Verify-RegistrationFix.ps1
# Run from Administrator PowerShell.
# Deletes the existing service, re-registers with the fixed binPath= argument
# (no leading space), verifies the registry ImagePath, then starts the service.
# ==============================================================================
$ErrorActionPreference = "Stop"

$ServiceName = "ThreatGuardAgent"
$InstallExe  = "C:\Program Files\ThreatGuard Agent\threatguard-agent.exe"

function Sep  { Write-Host ("-" * 60) -ForegroundColor DarkGray }
function OK   { param([string]$m) Write-Host "  OK: $m" -ForegroundColor Green }
function FAIL { param([string]$m) Write-Host "  FAIL: $m" -ForegroundColor Red ; exit 1 }
function INFO { param([string]$m) Write-Host "  $m" -ForegroundColor White }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Must be run as Administrator."
    exit 1
}

Write-Host ""
Write-Host "[1] Stop and delete existing registration" -ForegroundColor Cyan
Sep
& sc.exe stop $ServiceName 2>&1 | ForEach-Object { INFO "$_" }
Start-Sleep -Seconds 3
& sc.exe delete $ServiceName 2>&1 | ForEach-Object { INFO "$_" }
Start-Sleep -Seconds 2
OK "Old registration removed (or was not present)"

Write-Host ""
Write-Host "[2] Re-register service with sc.exe create" -ForegroundColor Cyan
Sep
# sc.exe requires 'binPath= <value>' with space after '='.
# BinaryPathName value: "C:\Program Files\ThreatGuard Agent\threatguard-agent.exe" --service-run
$scCmd = "sc.exe create $ServiceName binPath= `"\`"$InstallExe\`" --service-run`" start= auto DisplayName= `"ThreatGuard Endpoint Security Agent`""
INFO "Executing: $scCmd"
$createOutput = cmd.exe /c $scCmd 2>&1
$createExitCode = $LASTEXITCODE
$createOutput | ForEach-Object { INFO "$_" }
if ($createExitCode -ne 0) {
    FAIL "sc.exe create failed (exit $createExitCode)"
}
& sc.exe description $ServiceName "ThreatGuard endpoint security telemetry and monitoring agent service." | Out-Null
OK "Service registered via sc.exe create"

Write-Host ""
Write-Host "[3] Verify registry ImagePath has NO leading space and exact value" -ForegroundColor Cyan
Sep
$imagePath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName").ImagePath
INFO "Raw ImagePath: [$imagePath]"
$expectedPath = "`"$InstallExe`" --service-run"
if ($imagePath -eq $null) {
    FAIL "ImagePath is null - registry key not found"
} elseif ($imagePath[0] -eq ' ') {
    FAIL "ImagePath starts with SPACE - leading space bug still present!"
} elseif ($imagePath -ne $expectedPath) {
    FAIL "ImagePath [$imagePath] does not equal expected [$expectedPath]"
} else {
    OK "ImagePath matches expected exactly: $imagePath"
}

Write-Host ""
Write-Host "[4] sc.exe qc - full service config" -ForegroundColor Cyan
Sep
& sc.exe qc $ServiceName

Write-Host ""
Write-Host "[5] Start service" -ForegroundColor Cyan
Sep
& sc.exe start $ServiceName
$startCode = $LASTEXITCODE
INFO "sc.exe start exit code: $startCode"
if ($startCode -ne 0) {
    INFO "Checking Event Log for errors..."
    Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 -ErrorAction SilentlyContinue |
        ForEach-Object { INFO ("  [$($_.EntryType)] $($_.Message.Substring(0, [Math]::Min(200, $_.Message.Length)))") }
    FAIL "sc.exe start FAILED (exit $startCode)"
}

Write-Host ""
Write-Host "[6] Wait 5s then query state" -ForegroundColor Cyan
Sep
Start-Sleep -Seconds 5
$queryOut = & sc.exe query $ServiceName
$queryOut | ForEach-Object { INFO "$_" }
if ($queryOut -match "RUNNING") {
    OK "Service is RUNNING (STATE: 4 RUNNING)"
} else {
    FAIL "Service is NOT in RUNNING state"
}

Write-Host ""
Write-Host "[7] Check registry ImagePath one more time (confirm unchanged)" -ForegroundColor Cyan
Sep
$imagePath2 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName").ImagePath
INFO "ImagePath: [$imagePath2]"
if ($imagePath2 -eq $expectedPath) {
    OK "ImagePath confirmed unchanged and exact."
} else {
    FAIL "ImagePath changed or invalid: [$imagePath2]"
}

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host " Registration fix verified successfully." -ForegroundColor Green
Write-Host ("=" * 60) -ForegroundColor Green
