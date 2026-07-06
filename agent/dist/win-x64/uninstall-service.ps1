# Remove netflowAgent Windows service (run as Administrator)
param(
    [string]$ServiceName = "netflowAgent"
)

$ErrorActionPreference = "Stop"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping $ServiceName..."
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & sc.exe delete $ServiceName
    Write-Host "Service $ServiceName removed."
} else {
    Write-Host "Service $ServiceName not found."
}
