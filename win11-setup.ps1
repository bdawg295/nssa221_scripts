<#
    NSSA 221 – Windows 11 Client Setup (Fixed)
    
    Updates:
    - Prevents "crash" on domain join failure
    - Checks if already domain joined
    - Installs Thunderbird
#>

# -----------------------------
# MUST RUN AS ADMIN
# -----------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Run PowerShell as Administrator." -ForegroundColor Red
    Start-Sleep 5
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

if ([string]::IsNullOrWhiteSpace($DomainName) -or [string]::IsNullOrWhiteSpace($DC_IP)) {
    Write-Host "ERROR: Domain name and DC IP are required." -ForegroundColor Red
    Read-Host "Press Enter to exit..."
    exit 1
}

# -----------------------------
# SET DNS TO DC
# -----------------------------
Write-Host "[*] Setting DNS server to $DC_IP ..." -ForegroundColor Cyan

$Adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

if (-not $Adapter) {
    Write-Host "ERROR: No active network adapter found." -ForegroundColor Red
    Read-Host "Press Enter to exit..."
    exit 1
}

try {
    Set-DnsClientServerAddress -InterfaceIndex $Adapter.InterfaceIndex -ServerAddresses $DC_IP -ErrorAction Stop
    Write-Host "[+] DNS configured." -ForegroundColor Green
}
catch {
    Write-Host "[!] Failed to set DNS. Proceeding anyway, but this might fail." -ForegroundColor Yellow
}
Write-Host ""

# -----------------------------
# CONNECTIVITY CHECKS
# -----------------------------
Write-Host "[*] Testing connectivity to DC..." -ForegroundColor Cyan

if (-not (Test-Connection $DC_IP -Count 1 -Quiet)) {
    Write-Host "ERROR: Cannot reach Domain Controller ($DC_IP)." -ForegroundColor Red
    Write-Host "TROUBLESHOOT: Check firewall, IP config, or network adapter." -ForegroundColor Yellow
    Read-Host "Press Enter to exit..."
    exit 1
}

Write-Host "[+] DC reachable." -ForegroundColor Green

Write-Host "[*] Testing DNS resolution for $DomainName..." -ForegroundColor Cyan
try {
    Resolve-DnsName $DomainName -ErrorAction Stop | Out-Null
    Write-Host "[+] DNS resolution works." -ForegroundColor Green
}
catch {
    Write-Host "ERROR: DNS resolution failed." -ForegroundColor Red
    Write-Host "TROUBLESHOOT: Verify DNS role on DC and correct zone name." -ForegroundColor Yellow
    Read-Host "Press Enter to exit..."
    exit 1
}

Write-Host ""

# -----------------------------
# DOMAIN JOIN (ROBUST)
# -----------------------------
# Check if already joined to avoid errors
$ComputerSystem = Get-WmiObject Win32_ComputerSystem
if ($ComputerSystem.PartOfDomain -and ($ComputerSystem.Domain -eq $DomainName)) {
    Write-Host "[!] Computer is ALREADY joined to $DomainName. Skipping join." -ForegroundColor Yellow
}
else {
    Write-Host "[*] Joining domain $DomainName ..." -ForegroundColor Cyan
    $Cred = Get-Credential -Message "Enter DOMAIN credentials (Domain Admin or delegated user)"

    try {
        Add-Computer -DomainName $DomainName -Credential $Cred -ErrorAction Stop
        Write-Host "[+] Successfully joined domain." -ForegroundColor Green
    }
    catch {
        # STOP! Do not exit. Just warn the user.
        Write-Host "-----------------------------------------------------" -ForegroundColor Red
        Write-Host "ERROR: Domain join failed." -ForegroundColor Red
        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "-----------------------------------------------------" -ForegroundColor Red
        Write-Host "Script will CONTINUE to Thunderbird installation." -ForegroundColor Yellow
        Start-Sleep 3
    }
}

# ==========================================
# CLIENT MAIL SETUP
# ==========================================
Write-Host ""
Write-Host "=== Installing Mozilla Thunderbird ===" -ForegroundColor Cyan

# URL for standard US English installer
$ThunderbirdUrl = "https://download.mozilla.org/?product=thunderbird-latest&os=win64&lang=en-US"
$InstallerPath  = "$env:TEMP\ThunderbirdSetup.exe"

try {
    Write-Host "[*] Downloading Thunderbird..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $ThunderbirdUrl -OutFile $InstallerPath
    
    Write-Host "[*] Installing..."
    # /S is the silent switch for Thunderbird
    Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait -NoNewWindow
    
    Write-Host "[+] Thunderbird Installed Successfully!" -ForegroundColor Green
}
catch {
    Write-Host "[!] Error installing Thunderbird: $($_.Exception.Message)" -ForegroundColor Red
}

# -----------------------------
# REBOOT PROMPT
# -----------------------------
Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " Setup Complete." -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "You should reboot if the Domain Join was successful." -ForegroundColor Yellow

$Reboot = Read-Host "Do you want to reboot now? (Y/N)"
if ($Reboot -eq "Y") {
    Restart-Computer -Force
}