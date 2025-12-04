<#  
    lab2-win11-client.ps1
    Windows 11 Lab 2 automation script:
      - Set DNS server to the DC
      - Rename the computer (optional)
      - Join the domain
      - Place computer in an OU
      - Perform gpupdate
      - Reboot
#>

Write-Host "=== Windows 11 Lab 2 Setup ===" -ForegroundColor Cyan

# INPUTS
$domain = Read-Host "Enter domain FQDN (e.g. bmw7216.com)"
$dcIP   = Read-Host "Enter IP address of Domain Controller (e.g. 192.168.1.2)"

$newName = Read-Host "Enter NEW computer name (or press ENTER to skip rename)"
$ouPath = Read-Host "Enter FULL OU DN for the computer (e.g. OU=Workstations,DC=bmw7216,DC=com)"

$joinUser = Read-Host "Enter domain join account (e.g. Administrator)"
$joinPass = Read-Host "Enter password for $joinUser" -AsSecureString
$cred     = New-Object System.Management.Automation.PSCredential("$domain\$joinUser",$joinPass)

# 1. Set DNS to the DC
Write-Host "[*] Setting DNS to $dcIP ..." -ForegroundColor Cyan
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} |
    Set-DnsClientServerAddress -ServerAddresses $dcIP

# 2. Optional rename
if ($newName -ne "") {
    Write-Host "[*] Renaming computer to $newName ..." -ForegroundColor Cyan
    Rename-Computer -NewName $newName -Force
}

# 3. Join domain (+ OU placement)
Write-Host "[*] Joining domain $domain ..." -ForegroundColor Cyan

try {
    if ($ouPath -eq "") {
        Add-Computer -DomainName $domain -Credential $cred -Force -ErrorAction Stop
    } else {
        Add-Computer -DomainName $domain -Credential $cred -OUPath $ouPath -Force -ErrorAction Stop
    }
}
catch {
    Write-Host "ERROR: Domain join failed." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

Write-Host "[+] Successfully joined $domain." -ForegroundColor Green

# 4. Apply GPOs immediately
Write-Host "[*] Running gpupdate /force ..." -ForegroundColor Cyan
gpupdate /force

# 5. Reboot
Write-Host "[+] Setup complete. Rebooting now..." -ForegroundColor Green
Restart-Computer -Force
