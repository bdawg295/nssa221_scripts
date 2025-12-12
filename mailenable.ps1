# ============================================================
# MailEnable Full Server Setup (Standalone - Exam Ready)
# DNS + MailEnable + Mailboxes + Thunderbird Autoconfig
# ============================================================

# ----------------------------
# Admin check
# ----------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " MailEnable Full Server Setup" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# ----------------------------
# User input
# ----------------------------
$DomainName = Read-Host "Enter email domain (e.g. bmw7216.com)"
$MailUser   = Read-Host "Enter mailbox username (e.g. student)"
$MailPass   = Read-Host "Enter mailbox password"

# Smart IP Detection
$ServerIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.254*" -and $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1).IPAddress
Write-Host "[*] Detected Server IP: $ServerIP" -ForegroundColor Gray

$MailFQDN = "mail.$DomainName"
$AutoFQDN = "autoconfig.$DomainName"

# ----------------------------
# STEP 1: DNS RECORDS
# ----------------------------
if (Get-WindowsFeature DNS -ErrorAction SilentlyContinue | Where-Object Installed) {
    Import-Module DnsServer
    Write-Host "[*] Configuring DNS records..." -ForegroundColor Cyan

    # A Records
    if (-not (Get-DnsServerResourceRecord -ZoneName $DomainName -Name "mail" -ErrorAction SilentlyContinue)) {
        Add-DnsServerResourceRecordA -ZoneName $DomainName -Name "mail" -IPv4Address $ServerIP
    }
    if (-not (Get-DnsServerResourceRecord -ZoneName $DomainName -Name "autoconfig" -ErrorAction SilentlyContinue)) {
        Add-DnsServerResourceRecordA -ZoneName $DomainName -Name "autoconfig" -IPv4Address $ServerIP
    }

    # MX Record (Fixed syntax to ensure root domain)
    if (-not (Get-DnsServerResourceRecord -ZoneName $DomainName -RRType MX -ErrorAction SilentlyContinue)) {
        Add-DnsServerResourceRecordMX -Name "." -ZoneName $DomainName -MailExchange "$MailFQDN" -Preference 10
    }
    Write-Host "[+] DNS configured." -ForegroundColor Green
}
else {
    Write-Host "[!] DNS role not detected. Skipping DNS..." -ForegroundColor Yellow
}

# ----------------------------
# STEP 2: Install MailEnable (ROBUST)
# ----------------------------
$MEURL       = "https://www.mailenable.com/standard/MailEnable-Standard.exe"
$MEInstaller = "$env:TEMP\MailEnable-Standard.exe"
$MEBin       = "C:\Program Files (x86)\Mail Enable\Bin"

# 1. Download if missing
if (-not (Test-Path $MEInstaller)) {
    Write-Host "[*] Downloading MailEnable (using curl to bypass IE security)..." -ForegroundColor Cyan
    # Use curl.exe to avoid "file too small" errors
    & curl.exe -L -o "$MEInstaller" "$MEURL" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# 2. Install if not present
if (-not (Test-Path "$MEBin\MEAdmin.exe")) {
    Write-Host "[*] Installing MailEnable (This takes 1-2 mins)..." -ForegroundColor Cyan
    
    # Start process and WAIT for it to finish
    $Proc = Start-Process -FilePath $MEInstaller -ArgumentList "/S" -PassThru
    $Proc.WaitForExit()

    # Wait extra time for services to spin up
    Write-Host "[*] Waiting for services to register..." -ForegroundColor Cyan
    Start-Sleep -Seconds 20
    
    # Force Register Components (The "Fix" for COM errors)
    if (Test-Path "$MEBin\MEInstaller.exe") {
        Start-Process -FilePath "$MEBin\MEInstaller.exe" -ArgumentList "1" -Wait -WindowStyle Hidden
    }
}
else {
    Write-Host "[!] MailEnable already installed." -ForegroundColor Yellow
}

# ----------------------------
# STEP 3: Create Post Office
# ----------------------------
try {
    $oPO = New-Object -ComObject MEAOPO.Postoffice
    $oPO.Name    = $DomainName
    $oPO.Account = $DomainName
    $oPO.Status  = 1
    if ($oPO.AddPostoffice() -eq 1) {
        Write-Host "[+] Post Office created: $DomainName" -ForegroundColor Green
    } else {
        Write-Host "[!] Post Office exists." -ForegroundColor Yellow
    }

    $oDomain = New-Object -ComObject MEAOPO.Domain
    $oDomain.DomainName = $DomainName
    $oDomain.AccountName = $DomainName
    $oDomain.Status = 1
    $oDomain.AddDomain() | Out-Null
}
catch {
    Write-Host "ERROR: MailEnable COM objects failed to load." -ForegroundColor Red
    Write-Host "Try running the script one more time." -ForegroundColor Yellow
    exit 1
}

# ----------------------------
# STEP 4: Create Mailbox
# ----------------------------
try {
    $oMailbox = New-Object -ComObject MEAOPO.Mailbox
    $oMailbox.Postoffice = $DomainName
    $oMailbox.Mailbox    = $MailUser
    $oMailbox.Status     = 1
    $oMailbox.AddMailbox() | Out-Null

    $oLogin = New-Object -ComObject MEAOPO.Login
    $oLogin.Account  = $DomainName
    $oLogin.UserName = "$MailUser@$DomainName"
    $oLogin.Password = $MailPass
    $oLogin.Rights   = "USER"
    $oLogin.Status   = 1
    $oLogin.AddLogin() | Out-Null

    $oMap = New-Object -ComObject MEAOPO.AddressMap
    $oMap.Account = $DomainName
    $oMap.SourceAddress = "[SMTP:$MailUser@$DomainName]"
    $oMap.DestinationAddress = "[SF:$DomainName/$MailUser]"
    $oMap.AddAddressMap() | Out-Null

    Write-Host "[+] Mailbox created: $MailUser@$DomainName" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Failed to create mailbox." -ForegroundColor Red
}

# ----------------------------
# STEP 5: IIS Autoconfig
# ----------------------------
if (-not (Get-WindowsFeature Web-Server).Installed) {
    Write-Host "[*] Installing IIS..." -ForegroundColor Cyan
    Install-WindowsFeature Web-Server | Out-Null
}

$AutoDir = "C:\inetpub\wwwroot\mail"
New-Item $AutoDir -ItemType Directory -Force | Out-Null

$Xml = @"
<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="$DomainName">
    <domain>$DomainName</domain>
    <incomingServer type="imap">
      <hostname>$MailFQDN</hostname>
      <port>143</port>
      <socketType>plain</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>$MailFQDN</hostname>
      <port>25</port>
      <socketType>plain</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
"@

Set-Content "$AutoDir\config-v1.1.xml" $Xml
iisreset /noforce | Out-Null

Write-Host "[+] Thunderbird autoconfig enabled." -ForegroundColor Green

# ----------------------------
# DONE
# ----------------------------
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " MAIL SERVER READY" -ForegroundColor Green
Write-Host " Email:    $MailUser@$DomainName"
Write-Host " Password: $MailPass"
Write-Host "===================================================="