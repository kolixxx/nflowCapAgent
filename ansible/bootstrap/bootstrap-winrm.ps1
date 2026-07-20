# Run once in Windows PowerShell as Administrator on a fresh Windows host.
param(
    [Parameter(Mandatory = $true)]
    [string]$AnsibleController
)

$ErrorActionPreference = "Stop"

Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

$httpsListener = Get-ChildItem WSMan:\localhost\Listener |
    Where-Object { $_.Keys -contains "Transport=HTTPS" }

if (-not $httpsListener) {
    $certificate = New-SelfSignedCertificate `
        -DnsName $env:COMPUTERNAME `
        -CertStoreLocation Cert:\LocalMachine\My `
        -NotAfter (Get-Date).AddYears(5)

    New-Item `
        -Path WSMan:\localhost\Listener `
        -Transport HTTPS `
        -Address * `
        -CertificateThumbPrint $certificate.Thumbprint `
        -Force | Out-Null
}

# Do not leave an unencrypted HTTP listener enabled.
Get-ChildItem WSMan:\localhost\Listener |
    Where-Object { $_.Keys -contains "Transport=HTTP" } |
    Remove-Item -Recurse -Force

if (-not (Get-NetFirewallRule -Name "netflowAgent-Ansible-WinRM-HTTPS" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule `
        -Name "netflowAgent-Ansible-WinRM-HTTPS" `
        -DisplayName "Ansible WinRM HTTPS (collector only)" `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 5986 `
        -RemoteAddress $AnsibleController | Out-Null
}

Write-Host "WinRM HTTPS bootstrap complete on TCP 5986."
Write-Host "Lab uses a self-signed certificate; use a trusted certificate in production."
