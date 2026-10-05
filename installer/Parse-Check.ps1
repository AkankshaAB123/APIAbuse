param([string]$ScriptPath)
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -eq 0) {
    Write-Host "PARSE OK - 0 errors" -ForegroundColor Green
} else {
    Write-Host ("PARSE ERRORS: " + $errors.Count) -ForegroundColor Red
    foreach ($e in $errors) {
        Write-Host ("  Line " + $e.Extent.StartLineNumber + ": " + $e.Message) -ForegroundColor Red
    }
}
