<#
    NSSA 221 – Windows 11 Client Setup (Labs 1 & 2)

    What this does:
    - Sets DNS to the Domain Controller
    - Verifies connectivity
    - Joins the AD domain
    - Reboots automatically

    Run from an elevated PowerShell:
        Set-ExecutionPolicy Bypass -Scope Process -Force
        .\win11-domain-join.ps1
#>

# -----------------------------
# MUST RUN AS ADMIN
# -----------------------------
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

    Write-Host "ERROR: Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " NSSA 221 – Windows 11 Domain Join Script" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------
# USER INPUT
# -----------------------------
$DomainName = Read-Host "Enter AD domain name (e.g. bmw7216.com)"
$DC_IP      = Read-Host "Enter Domain Controller IP (DNS server)"

if ([string]::IsNullOrWhiteSpace($DomainName) -or
    [string]::IsNullOrWhiteSpace($DC_IP)) {

    Write-Host "ERROR: Domain name and DC IP are required." -ForegroundColor Red
    exit 1
}

# -----------------------------
# SET DNS TO DC
# -----------------------------
Write-Host "[*] Setting DNS server to $DC_IP ..." -ForegroundColor Cyan

$Adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

if (-not $Adapter) {
    Write-Host "ERROR: No active network adapter found." -ForegroundColor Red
    exit 1
}

Set-DnsClientServerAddress `
    -InterfaceIndex $Adapter.InterfaceIndex `
    -ServerAddresses $DC_IP

Write-Host "[+] DNS configured." -ForegroundColor Green
Write-Host ""

# -----------------------------
# CONNECTIVITY CHECKS
# -----------------------------
Write-Host "[*] Testing connectivity to DC..." -ForegroundColor Cyan

if (-not (Test-Connection $DC_IP -Count 2 -Quiet)) {
    Write-Host "ERROR: Cannot reach Domain Controller." -ForegroundColor Red
    Write-Host "TROUBLESHOOT: Check firewall, IP config, or pfSense." -ForegroundColor Yellow
    exit 1
}

Write-Host "[+] DC reachable." -ForegroundColor Green

Write-Host "[*] Testing DNS resolution..." -ForegroundColor Cyan
try {
    Resolve-DnsName $DomainName -ErrorAction Stop | Out-Null
    Write-Host "[+] DNS resolution works." -ForegroundColor Green
}
catch {
    Write-Host "ERROR: DNS resolution failed." -ForegroundColor Red
    Write-Host "TROUBLESHOOT: Verify DNS role on DC and correct zone name." -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# -----------------------------
# DOMAIN JOIN
# -----------------------------
Write-Host "[*] Joining domain $DomainName ..." -ForegroundColor Cyan

$Cred = Get-Credential -Message "Enter DOMAIN credentials (Domain Admin or delegated user)"

try {
    Add-Computer `
        -DomainName $DomainName `
        -Credential $Cred `
        -ErrorAction Stop

    Write-Host "[+] Successfully joined domain." -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Domain join failed." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "TROUBLESHOOT:" -ForegroundColor Yellow
    Write-Host " - Ensure time is synced with DC" -ForegroundColor Yellow
    Write-Host " - Ensure user has permission to join domain" -ForegroundColor Yellow
    exit 1
}

# ==========================================
# CLIENT MAIL SETUP
# ==========================================

# 1. Check DNS Settings (Critical)
# The client MUST use the DC as its DNS server to find 'autoconfig'
$DnsServer = "192.168.1.2" # CHANGE THIS TO YOUR DC IP IF DIFFERENT
$Interface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

Write-Host "=== Setting DNS to DC ($DnsServer) ===" -ForegroundColor Cyan
Set-DnsClientServerAddress -InterfaceIndex $Interface.ifIndex -ServerAddresses $DnsServer
Write-Host "[+] DNS configured." -ForegroundColor Green

# 2. Install Thunderbird Silently
Write-Host "=== Installing Mozilla Thunderbird ===" -ForegroundColor Cyan

# URL for standard US English installer
$ThunderbirdUrl = "https://download.mozilla.org/?product=thunderbird-latest&os=win64&lang=en-US"
$InstallerPath  = "$env:TEMP\ThunderbirdSetup.exe"

try {
    Write-Host "[*] Downloading Thunderbird..."
    Invoke-WebRequest -Uri $ThunderbirdUrl -OutFile $InstallerPath
    
    Write-Host "[*] Installing..."
    # /S is the silent switch for Thunderbird
    Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait -NoNewWindow
    
    Write-Host "[+] Thunderbird Installed Successfully!" -ForegroundColor Green
    Write-Host "    Open Thunderbird, enter 'user@$((Get-WmiObject Win32_ComputerSystem).Domain)', and password." -ForegroundColor Yellow
}
catch {
    Write-Host "[!] Error installing Thunderbird: $($_.Exception.Message)" -ForegroundColor Red
}

# -----------------------------
# REBOOT
# -----------------------------
Write-Host ""
Write-Host "[!] Rebooting in 10 seconds to complete domain join..." -ForegroundColor Yellow
Start-Sleep 20
Restart-Computer -Force
