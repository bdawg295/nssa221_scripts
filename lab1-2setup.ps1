<# 
    dc_setup.ps1

    High-level:
    - Optionally install AD DS, DNS, DHCP roles
    - Optionally promote the box to a new forest/domain
    - Optionally configure DHCP scope + exclusions + options
    - Optionally create Organizational Units (OUs)
    - Optionally create batches of AD users like name1, name2, ...
    - Optionally create and link standard GPOs:
        * DenyControlPanel on the domain
        * OU-specific wallpaper GPO

    Run as:  (from elevated PowerShell)
        irm https://raw.githubusercontent.com/YOURUSER/YOURREPO/main/dc_setup.ps1 | iex
#>

#----------------------------#
# Helper: Yes/No prompt      #
#----------------------------#
function Prompt-YesNo {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    while ($true) {
        $answer = Read-Host "$Message [Y/N]"
        switch ($answer.ToUpper()) {
            'Y' { return $true }
            'N' { return $false }
            default { Write-Host "Please type Y or N." -ForegroundColor Yellow }
        }
    }
}

#----------------------------#
# Safety: Must be Administrator
#----------------------------#
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator"
)) {
    Write-Host "ERROR: This script MUST be run in an elevated PowerShell session." -ForegroundColor Red
    return
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Windows Server DC / AD / DNS / DHCP / OU / User / GPO setup" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

#----------------------------------------#
# Basic Domain Information (used by all) #
#----------------------------------------#
$DomainName = Read-Host "Enter your AD domain FQDN (e.g. abc1234.com)"
if ([string]::IsNullOrWhiteSpace($DomainName)) {
    Write-Host "Domain name is required. Exiting." -ForegroundColor Red
    return
}

$domainParts = $DomainName.Split('.')
$DomainDN    = ($domainParts | ForEach-Object { "DC=$_" }) -join ','
$DefaultNetBIOS = $domainParts[0].ToUpper()

Write-Host "Domain FQDN : $DomainName" -ForegroundColor Green
Write-Host "Domain DN   : $DomainDN" -ForegroundColor Green
Write-Host "NetBIOS def.: $DefaultNetBIOS" -ForegroundColor Green
Write-Host ""

#----------------------------#
# 1) Install Roles (optional)
#----------------------------#
if (Prompt-YesNo "Install AD DS, DNS, and DHCP roles on this server?") {
    Write-Host "[*] Installing AD-Domain-Services, DNS, and DHCP Server roles..." -ForegroundColor Cyan
    Install-WindowsFeature -Name AD-Domain-Services, DNS, DHCP -IncludeManagementTools | Out-Null
    Write-Host "[+] Roles installed (or already present)." -ForegroundColor Green
    Write-Host ""
}

#-----------------------------------------
# 2) Promote server to a new forest (opt)
#-----------------------------------------
if (Prompt-YesNo "Promote this server to a NEW forest/domain ($DomainName)? (This will eventually reboot)") {
    try {
        Import-Module ADDSDeployment -ErrorAction Stop

        $NetBIOSName = Read-Host "Enter NetBIOS domain name [`$DefaultNetBIOS by default]"
        if ([string]::IsNullOrWhiteSpace($NetBIOSName)) {
            $NetBIOSName = $DefaultNetBIOS
        }

        $dsrmPwd = Read-Host "Enter DSRM (Directory Services Restore Mode) password" -AsSecureString

        Write-Host "[*] Promoting server to domain controller for $DomainName ..." -ForegroundColor Cyan
        Install-ADDSForest `
            -DomainName $DomainName `
            -DomainNetbiosName $NetBIOSName `
            -SafeModeAdministratorPassword $dsrmPwd `
            -InstallDNS `
            -Force

        Write-Host "[!] The server will likely reboot after promotion. Re-run this script afterwards for DHCP/OUs/users/GPOs." -ForegroundColor Yellow
        return
    }
    catch {
        Write-Host "ERROR during domain promotion: $_" -ForegroundColor Red
        return
    }
}

# At this point we assume we're already a DC for $DomainName.

#---------------------------------#
# 3) Configure DHCP (optional)    #
#---------------------------------#
if (Prompt-YesNo "Configure DHCP scope, exclusions, and options?") {
    try {
        Import-Module DhcpServer -ErrorAction Stop
    }
    catch {
        Write-Host "ERROR: DhcpServer PowerShell module not available. Is the DHCP role installed?" -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "=== DHCP Server Configuration ===" -ForegroundColor Cyan
    $ServerIP = Read-Host "Enter this server's STATIC IPv4 address (e.g. 192.168.10.10)"
    $ScopeNetworkID = Read-Host "Enter network ID for the scope (e.g. 192.168.10.0)"
    $ScopeName = Read-Host "Enter a name for the DHCP scope (e.g. LabScope)"
    $ScopeStart = Read-Host "Enter FIRST dynamic IP (e.g. 192.168.10.11)"
    $ScopeEnd   = Read-Host "Enter LAST dynamic IP  (e.g. 192.168.10.253)"
    $SubnetMask = Read-Host "Enter subnet mask (e.g. 255.255.255.0)"

    # Authorize DHCP server in AD if needed
    if (-not (Get-DhcpServerInDC -ErrorAction SilentlyContinue)) {
        Write-Host "[*] Authorizing this DHCP server in Active Directory..." -ForegroundColor Cyan
        Add-DhcpServerInDC -DnsName $env:COMPUTERNAME -IpAddress $ServerIP
        Write-Host "[+] DHCP server authorized in AD." -ForegroundColor Green
    }

    # Create scope
    if (-not (Get-DhcpServerv4Scope -ScopeId $ScopeNetworkID -ErrorAction SilentlyContinue)) {
        Write-Host "[*] Creating DHCP scope '$ScopeName' ($ScopeStart - $ScopeEnd)..." -ForegroundColor Cyan
        New-DhcpServerv4Scope `
            -Name $ScopeName `
            -StartRange $ScopeStart `
            -EndRange $ScopeEnd `
            -SubnetMask $SubnetMask `
            -State Active | Out-Null
        Write-Host "[+] Scope created and activated." -ForegroundColor Green
    }
    else {
        Write-Host "[!] Scope with ScopeId $ScopeNetworkID already exists; skipping creation." -ForegroundColor Yellow
    }

    # Exclusion ranges for statics (gateway, servers, etc.)
    if (Prompt-YesNo "Configure one or more EXCLUSION ranges for static IPs (gateway/servers)?") {
        $more = $true
        while ($more) {
            $ExStart = Read-Host "  Exclusion START IP (e.g. 192.168.10.1)"
            $ExEnd   = Read-Host "  Exclusion END IP   (e.g. 192.168.10.10)"
            Write-Host "  [*] Adding exclusion range $ExStart - $ExEnd ..." -ForegroundColor Cyan

            Add-DhcpServerv4ExclusionRange `
                -ScopeId $ScopeNetworkID `
                -StartRange $ExStart `
                -EndRange $ExEnd

            Write-Host "  [+] Exclusion range added." -ForegroundColor Green
            $more = Prompt-YesNo "  Add another exclusion range?"
        }
    }
    else {
        Write-Host "[!] No exclusion ranges configured. DHCP may assign ALL addresses in the scope." -ForegroundColor Yellow
    }

    # Scope options: gateway + DNS + domain name
    $Gateway = Read-Host "Enter default gateway IP (pfSense LAN, etc. e.g. 192.168.10.254)"
    $PrimaryDNS = Read-Host "Enter PRIMARY DNS server IP (usually this DC: $ServerIP)"
    $SecondaryDNS = Read-Host "Enter SECONDARY DNS server IP (optional, blank to skip)"

    $DnsServers = @()
    if (-not [string]::IsNullOrWhiteSpace($PrimaryDNS))   { $DnsServers += $PrimaryDNS }
    if (-not [string]::IsNullOrWhiteSpace($SecondaryDNS)) { $DnsServers += $SecondaryDNS }

    Write-Host "[*] Setting DHCP scope options (router/DNS/domain)..." -ForegroundColor Cyan
    Set-DhcpServerv4OptionValue `
        -ScopeId   $ScopeNetworkID `
        -Router    $Gateway `
        -DnsServer $DnsServers `
        -DnsDomain $DomainName

    Write-Host "[+] DHCP configuration complete." -ForegroundColor Green
    Write-Host ""
}

#---------------------------------#
# 4) Create OUs (optional)        #
#---------------------------------#
try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "ERROR: ActiveDirectory module not available. Is AD DS installed?" -ForegroundColor Red
    return
}

if (Prompt-YesNo "Create one or more Organizational Units (OUs)?") {
    Write-Host ""
    Write-Host "=== OU Creation ===" -ForegroundColor Cyan
    $ouCount = [int](Read-Host "How many OUs do you want to create?")
    for ($i = 1; $i -le $ouCount; $i++) {
        $ouName = Read-Host "Enter name for OU #$i (e.g. Ramones, Weezer)"
        $ouPath = "OU=$ouName,$DomainDN"

        if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$ouName)" -SearchBase $DomainDN -ErrorAction SilentlyContinue)) {
            Write-Host "[*] Creating OU '$ouName' at $ouPath ..." -ForegroundColor Cyan
            New-ADOrganizationalUnit `
                -Name $ouName `
                -Path $DomainDN `
                -ProtectedFromAccidentalDeletion $true | Out-Null
            Write-Host "[+] OU '$ouName' created." -ForegroundColor Green
        }
        else {
            Write-Host "[!] OU '$ouName' already exists; skipping." -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

#---------------------------------#
# 5) Bulk numbered users (opt)    #
#---------------------------------#
if (Prompt-YesNo "Create a batch of numbered users (name1, name2, name3, ...)?") {
    Write-Host ""
    Write-Host "=== Bulk User Creation ===" -ForegroundColor Cyan

    $TargetOUName = Read-Host "Enter the EXISTING OU name to put these users in (e.g. Weezer)"
    $TargetOUPath = "OU=$TargetOUName,$DomainDN"

    # Basic check that OU exists
    if (-not (Get-ADOrganizationalUnit -Identity $TargetOUPath -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: OU '$TargetOUPath' not found. Create it first." -ForegroundColor Red
    }
    else {
        $BaseName = Read-Host "Enter base username (e.g. 'user' => user1, user2...)"
        $StartIndex = [int](Read-Host "Enter starting number (e.g. 1)")
        $UserCount  = [int](Read-Host "How many users do you want to create?")
        $PasswordSec = Read-Host "Enter password for ALL created users" -AsSecureString

        $AddToGroup = $false
        $GroupName  = $null
        if (Prompt-YesNo "Add all of these users to an additional group (e.g. Domain Admins)?") {
            $GroupName = Read-Host "Enter group name (e.g. 'Domain Admins' or a custom group)"
            $AddToGroup = $true
        }

        $usersCreated = @()
        for ($i = 0; $i -lt $UserCount; $i++) {
            $n = $StartIndex + $i
            $sam = "$BaseName$n"
            $upn = "$sam@$DomainName"
            $name = $sam

            Write-Host "[*] Creating user '$sam' in $TargetOUPath ..." -ForegroundColor Cyan
            if (-not (Get-ADUser -Identity $sam -ErrorAction SilentlyContinue)) {
                New-ADUser `
                    -Name $name `
                    -SamAccountName $sam `
                    -UserPrincipalName $upn `
                    -Path $TargetOUPath `
                    -AccountPassword $PasswordSec `
                    -Enabled $true `
                    -PasswordNeverExpires $true `
                    -ChangePasswordAtLogon $false | Out-Null

                $usersCreated += $sam
                Write-Host "[+] Created user $sam" -ForegroundColor Green
            }
            else {
                Write-Host "[!] User $sam already exists; skipping." -ForegroundColor Yellow
            }
        }

        # Optionally add to group
        if ($AddToGroup -and $usersCreated.Count -gt 0) {
            Write-Host "[*] Adding users to group '$GroupName'..." -ForegroundColor Cyan
            foreach ($u in $usersCreated) {
                try {
                    Add-ADGroupMember -Identity $GroupName -Members $u -ErrorAction Stop
                    Write-Host "  [+] $u added to $GroupName" -ForegroundColor Green
                }
                catch {
                    Write-Host "  [!] Failed to add $u to $GroupName : $_" -ForegroundColor Yellow
                }
            }
        }

        Write-Host "[+] Bulk user creation complete." -ForegroundColor Green
    }
    Write-Host ""
}

#---------------------------------#
# 6) GPOs & links (optional)      #
#---------------------------------#
try {
    Import-Module GroupPolicy -ErrorAction Stop
}
catch {
    Write-Host "WARNING: GroupPolicy module not available. Skipping GPO section." -ForegroundColor Yellow
    return
}

# 6a) Deny Control Panel GPO on domain
if (Prompt-YesNo "Create & link a 'Deny Control Panel' GPO at the DOMAIN level?") {
    Write-Host ""
    Write-Host "=== Domain GPO: Deny Control Panel ===" -ForegroundColor Cyan
    $GpoName = Read-Host "Enter GPO name [default: DenyControlPanel]"
    if ([string]::IsNullOrWhiteSpace($GpoName)) { $GpoName = "DenyControlPanel" }

    $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $gpo) {
        Write-Host "[*] Creating GPO '$GpoName'..." -ForegroundColor Cyan
        $gpo = New-GPO -Name $GpoName -Comment "Created by DC setup script to restrict Control Panel"
        Write-Host "[+] GPO '$GpoName' created." -ForegroundColor Green
    }
    else {
        Write-Host "[!] GPO '$GpoName' already exists; reusing." -ForegroundColor Yellow
    }

    Write-Host "[*] Linking GPO '$GpoName' to domain '$DomainName'..." -ForegroundColor Cyan
    New-GPLink -Name $GpoName -Target $DomainName -Enforced:$false -ErrorAction SilentlyContinue | Out-Null

    # Configure NoControlPanel = 1
    Write-Host "[*] Setting registry value to prohibit Control Panel access..." -ForegroundColor Cyan
    Set-GPRegistryValue `
        -Name $GpoName `
        -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -ValueName "NoControlPanel" `
        -Type DWord `
        -Value 1

    Write-Host "[+] GPO '$GpoName' configured and linked to domain. Normal domain users will have Control Panel blocked after gpupdate." -ForegroundColor Green
    Write-Host ""
}

# 6b) Wallpaper GPO for OU
if (Prompt-YesNo "Create & link a DESKTOP WALLPAPER GPO for a specific OU?") {
    Write-Host ""
    Write-Host "=== OU GPO: Desktop Wallpaper ===" -ForegroundColor Cyan

    $GpoName2 = Read-Host "Enter GPO name [default: OU-Wallpaper]"
    if ([string]::IsNullOrWhiteSpace($GpoName2)) { $GpoName2 = "OU-Wallpaper" }

    $TargetOUName2 = Read-Host "Enter target OU name (e.g. Ramones, Weezer)"
    $TargetOUDN2   = "OU=$TargetOUName2,$DomainDN"

    if (-not (Get-ADOrganizationalUnit -Identity $TargetOUDN2 -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: OU '$TargetOUDN2' not found. Cannot link wallpaper GPO." -ForegroundColor Red
    }
    else {
        $WallpaperPath = Read-Host "Enter UNC path to wallpaper image (e.g. \\SERVER\Share\wallpaper.jpg)"
        $Style = Read-Host "Enter wallpaper style number (0=Center, 2=Stretch) [default 2]"
        if ([string]::IsNullOrWhiteSpace($Style)) { $Style = "2" }

        $gpo2 = Get-GPO -Name $GpoName2 -ErrorAction SilentlyContinue
        if (-not $gpo2) {
            Write-Host "[*] Creating GPO '$GpoName2'..." -ForegroundColor Cyan
            $gpo2 = New-GPO -Name $GpoName2 -Comment "Created by DC setup script for OU wallpaper"
            Write-Host "[+] GPO '$GpoName2' created." -ForegroundColor Green
        }
        else {
            Write-Host "[!] GPO '$GpoName2' already exists; reusing." -ForegroundColor Yellow
        }

        Write-Host "[*] Linking GPO '$GpoName2' to OU '$TargetOUDN2'..." -ForegroundColor Cyan
        New-GPLink -Name $GpoName2 -Target $TargetOUDN2 -Enforced:$false -ErrorAction SilentlyContinue | Out-Null

        # Configure wallpaper settings
        Write-Host "[*] Setting wallpaper registry values in GPO..." -ForegroundColor Cyan
        Set-GPRegistryValue `
            -Name $GpoName2 `
            -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
            -ValueName "Wallpaper" `
            -Type String `
            -Value $WallpaperPath

        Set-GPRegistryValue `
            -Name $GpoName2 `
            -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
            -ValueName "WallpaperStyle" `
            -Type String `
            -Value $Style

        Write-Host "[+] Wallpaper GPO '$GpoName2' configured and linked to OU '$TargetOUName2'." -ForegroundColor Green
        Write-Host "    Remember to run 'gpupdate /force' on a client in that OU to see it take effect." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " All selected domain controller tasks have completed." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
