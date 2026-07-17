# Remove netflowAgent Windows service (run as Administrator)
param(
    [string]$ServiceName = "netflowAgent",
    [switch]$PurgeFiles,
    [string]$InstallDir = "C:\netflowAgent",
    [string]$LogDir = "C:\ProgramData\netflowAgent"
)

$ErrorActionPreference = "Stop"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping $ServiceName..."
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & sc.exe delete $ServiceName | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Could not delete service $ServiceName (sc.exe exit code $LASTEXITCODE)."
    }

    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        throw "Service $ServiceName is still pending deletion. Reboot Windows, then run this script again."
    }
    Write-Host "Service $ServiceName removed."
} else {
    Write-Host "Service $ServiceName not found."
}

if ($PurgeFiles) {
    $pathsToRemove = @()
    foreach ($path in @($InstallDir, $LogDir)) {
        $fullPath = [System.IO.Path]::GetFullPath($path)
        $root = [System.IO.Path]::GetPathRoot($fullPath)
        if ($fullPath -eq $root) {
            throw "Refusing to remove filesystem root: $fullPath"
        }
        $pathsToRemove += $fullPath
    }

    # The script may itself live in InstallDir; leave that directory before removal.
    Set-Location $env:TEMP
    foreach ($path in $pathsToRemove) {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $path) {
            throw "Could not completely remove $path. Close open files or reboot, then remove it manually."
        }
    }
    Write-Host "Agent files and logs removed."
    Write-Host "System dependencies kept: Npcap and Rust/build tools."
} else {
    Write-Host "Files kept: $InstallDir, $LogDir"
    Write-Host "For a complete agent cleanup, run: .\uninstall-service.ps1 -PurgeFiles"
}
