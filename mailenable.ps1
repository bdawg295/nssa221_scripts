# ============================================================
# MailEnable Full Server Setup (Standalone)
# DNS + MailEnable + Mailboxes + Thunderbird Autoconfig
# ============================================================

# ----------------------------
# Admin check
# ----------------------------
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " MailEnable Full Server Setup (Exam Mode)" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# ----------------------------
# User input
# ----------------------------
$DomainName = Read-Host "Enter email domain (e.g. bmw7216.com)"
$MailUser  = Read-Host "Enter mailbox username (e.g. student)"
$MailPass  = Read-Host "Enter mailbox password"

$ServerIP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "169.254*" -and $_.InterfaceAlias -notlike "*Loopback*" } |
    Select-Object -First 1).IPAddress

$MailFQDN = "mail.$DomainName"
$AutoFQDN = "autoconfig.$DomainName"

# ----------------------------
# STEP 1: DNS RECORDS (If DNS role exists)
# ----------------------------
if (Get-WindowsFeature DNS -ErrorAction SilentlyContinue | Where-Object Installed) {
    Import-Module DnsServer

    Write-Host "[*] Configuring DNS records..." -ForegroundColor Cyan

    # A record: mail.domain
    if (-not (Get-DnsServerResourceRecord -ZoneName $DomainName -Name "mail" -ErrorAction SilentlyContinue)) {
        Add-DnsServerResourceRecordA -ZoneName $DomainName -Name "mail" -IPv4Address $ServerIP
    }

    # A record: autoconfig.domain
    if (-not (Get-DnsServerResourceRecord -ZoneName $DomainName -Name "autoconfig" -ErrorAction SilentlyContinue)) {
        Add-DnsServerResourceRecordA -ZoneName $DomainName -Name "autoconfig" -IPv4Address $ServerIP
    }

    # MX record
    if (-not (Get-DnsServerResourceRecord -ZoneName $DomainName -RRType MX -ErrorAction SilentlyContinue)) {
        Add-DnsServerResourceRecordMX `
            -ZoneName $DomainName `
            -MailExchange "$MailFQDN." `
            -Preference 10
    }

    Write-Host "[+] DNS configured." -ForegroundColor Green
}
else {
    Write-Host "[!] DNS role not present — skipping DNS config." -ForegroundColor Yellow
}

# ----------------------------
# STEP 2: Install MailEnable
# ----------------------------
$MEInstaller = "C:\Installers\MailEnable-Standard.exe"
$MEPath = "C:\Program Files (x86)\Mail Enable\Bin\MEAdmin.exe"

if (-not (Test-Path $MEPath)) {
    Write-Host "[*] Installing MailEnable..." -ForegroundColor Cyan
    Start-Process $MEInstaller -ArgumentList "/SILENT" -Wait
    Start-Sleep 10
}
else {
    Write-Host "[!] MailEnable already installed." -ForegroundColor Yellow
}

# ----------------------------
# STEP 3: Create Post Office
# ----------------------------
$oPO = New-Object -ComObject MEAOPO.Postoffice
$oPO.Name    = $DomainName
$oPO.Account = $DomainName
$oPO.Status  = 1
$oPO.AddPostoffice() | Out-Null

$oDomain = New-Object -ComObject MEAOPO.Domain
$oDomain.DomainName = $DomainName
$oDomain.AccountName = $DomainName
$oDomain.Status = 1
$oDomain.AddDomain() | Out-Null

Write-Host "[+] Post Office created: $DomainName" -ForegroundColor Green

# ----------------------------
# STEP 4: Create Mailbox
# ----------------------------
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

# ----------------------------
# STEP 5: IIS Autoconfig (Thunderbird)
# ----------------------------
if (-not (Get-WindowsFeature Web-Server).Installed) {
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
