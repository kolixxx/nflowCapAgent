# Remove netflowAgent Windows service (run as Administrator)
param(
    [string]$InstallDir = "C:\netflowAgent"
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir "netflowAgent.exe"

if (Test-Path $exe) {
    & $exe --uninstall-service
} else {
    Stop-Service netflowAgent -Force -ErrorAction SilentlyContinue
    & sc.exe delete netflowAgent
}

Write-Host "Done."
