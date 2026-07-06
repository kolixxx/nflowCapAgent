# Install netflowAgent as Windows service (run as Administrator)
param(
    [string]$InstallDir = "C:\netflowAgent",
    [string]$Config = "$InstallDir\config.toml"
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir "netflowAgent.exe"

if (-not (Test-Path $exe)) {
    Write-Error "Not found: $exe"
}

$logDir = "C:\ProgramData\netflowAgent"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$existing = Get-Service -Name netflowAgent -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping existing service..."
    Stop-Service netflowAgent -Force -ErrorAction SilentlyContinue
    & sc.exe delete netflowAgent | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "Installing service from $exe"
& $exe --install-service --config $Config

Write-Host "Starting service..."
Start-Service netflowAgent
Get-Service netflowAgent
Write-Host "Log file: C:\ProgramData\netflowAgent\agent.log"
