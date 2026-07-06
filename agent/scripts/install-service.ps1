# Install netflowAgent as Windows service (run as Administrator)
param(
    [string]$InstallDir = "C:\netflowAgent",
    [string]$Config = ""
)

$ErrorActionPreference = "Stop"
$svcName = "netflowAgent"

if (-not $Config) {
    $Config = Join-Path $InstallDir "config.toml"
}

$exe = Join-Path $InstallDir "netflowAgent.exe"

if (-not (Test-Path $exe)) {
    Write-Error "Not found: $exe"
}
if (-not (Test-Path $Config)) {
    Write-Error "Not found: $Config"
}

$logDir = "C:\ProgramData\netflowAgent"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing existing service..."
    Stop-Service $svcName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & sc.exe delete $svcName | Out-Null
    Start-Sleep -Seconds 2
}

# BinaryPathName: quoted exe + CLI args (required for --run-as-service)
$binaryPathName = "`"$exe`" --run-as-service --config `"$Config`""

Write-Host "Installing service $svcName"
Write-Host "  BinaryPathName: $binaryPathName"

New-Service `
    -Name $svcName `
    -BinaryPathName $binaryPathName `
    -DisplayName "netflowAgent NetFlow Export" `
    -StartupType Automatic `
    -Description "Exports host network flows as NetFlow v9 to nfcapd collector"

Write-Host "Starting service..."
Start-Service $svcName
Get-Service $svcName
Write-Host "Log file: C:\ProgramData\netflowAgent\agent.log"
