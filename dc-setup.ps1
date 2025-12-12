<#
    dc-setup.ps1

    High-level:
    - Optionally install AD DS, DNS, DHCP roles
    - Optionally promote the box to a NEW forest/domain (first run only)
    - Optionally configure DHCP scope + exclusions + options
    - Optionally create Organizational Units (OUs)
    - Optionally create batches of AD users (name1, name2, ...)
    - Optionally create and link GPOs:
        * Deny Control Panel at the domain
        * Wallpaper GPO for an OU

    Intended workflow
    -----------------
    1) Fresh Windows Server:
         - (Optionally) set NIC to static IP / correct gateway / DNS = itself.
         - Run this script.
         - Say Y to roles.
         - Say Y to "Promote to new forest/domain" (first run only).
         - Server reboots after promotion.

    2) After reboot:
         - Run this script again.
         - It detects it's already a DC, skips promotion.
         - Use it to configure DHCP / OUs / users / GPOs.

    Run from elevated PowerShell:
         Set-ExecutionPolicy Bypass -Scope Process -Force
         iex (irm "https://raw.githubusercontent.com/bdawg295/nssa221_scripts/main/dc-setup.ps1")
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
    Write-Host "TROUBLESHOOT: Right-click PowerShell and choose 'Run as administrator'." -ForegroundColor Yellow
    return
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Windows Server DC / AD / DNS / DHCP / OU / User / GPO setup" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "If something fails, look for RED 'ERROR' lines and 'TROUBLESHOOT' hints." -ForegroundColor Yellow
Write-Host ""

#------------------------------------------------#
# Detect whether this box is already a DC or not #
#------------------------------------------------#
$cs         = Get-WmiObject Win32_ComputerSystem
$domainRole = $cs.DomainRole        # 0-5, 4/5 = DC
$IsDC       = $domainRole -ge 4

$DomainName     = $null
$DomainDN       = $null
$DefaultNetBIOS = $null

if ($IsDC) {
    # Already a DC – pull info from AD
    Write-Host "[*] Machine reports as a Domain Controller. Querying AD for domain info..." -ForegroundColor Cyan
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adDomain       = Get-ADDomain
        $DomainName     = $adDomain.DNSRoot
        $DomainDN       = $adDomain.DistinguishedName
        $DefaultNetBIOS = $adDomain.NetBIOSName

        Write-Host "[+] Existing domain detected:" -ForegroundColor Green
        Write-Host "    FQDN   : $DomainName" -ForegroundColor Green
        Write-Host "    DN     : $DomainDN" -ForegroundColor Green
        Write-Host "    NetBIOS: $DefaultNetBIOS" -ForegroundColor Green
        Write-Host ""
    } catch {
        Write-Host "ERROR: This machine thinks it's a DC but AD cmdlets failed." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host "TROUBLESHOOT:" -ForegroundColor Yellow
        Write-Host " - Make sure AD DS role is actually installed." -ForegroundColor Yellow
        Write-Host " - If this is right after promotion, reboot and run the script again." -ForegroundColor Yellow
        Write-Host " - If AD is broken, you may need to re-image or re-promote." -ForegroundColor Yellow
        return
    }
}
else {
    # Not a DC yet – ask user for domain info
    $DomainName = Read-Host "Enter your AD domain FQDN (e.g. abc1234.com)"
    if ([string]::IsNullOrWhiteSpace($DomainName)) {
        Write-Host "Domain name is required. Exiting." -ForegroundColor Red
        return
    }

    $domainParts     = $DomainName.Split('.')
    $DomainDN        = ($domainParts | ForEach-Object { "DC=$_" }) -join ','
    $DefaultNetBIOS  = $domainParts[0].ToUpper()

    Write-Host "Domain FQDN : $DomainName" -ForegroundColor Green
    Write-Host "Domain DN   : $DomainDN" -ForegroundColor Green
    Write-Host "NetBIOS def.: $DefaultNetBIOS" -ForegroundColor Green
    Write-Host ""
}

#-----------------------------------------#
# Ensure correct computer hostname
#-----------------------------------------#
if (-not $IsDC) {

    Write-Host ""
    Write-Host "=== Hostname Configuration ===" -ForegroundColor Cyan

    $CurrentName = (Get-ComputerInfo).CsName

    $DesiredShortName = Read-Host "Enter desired COMPUTER NAME (short name, e.g. DC1)"
    if ([string]::IsNullOrWhiteSpace($DesiredShortName)) {
        Write-Host "ERROR: Computer name cannot be blank." -ForegroundColor Red
        return
    }

    if ($CurrentName -ieq $DesiredShortName) {
        Write-Host "[+] Computer name already set to '$CurrentName'. Skipping rename." -ForegroundColor Green
    }
    else {
        Write-Host "[*] Renaming computer from '$CurrentName' to '$DesiredShortName'..." -ForegroundColor Cyan

        try {
            Rename-Computer -NewName $DesiredShortName -Force -ErrorAction Stop
            Write-Host "[+] Computer renamed successfully." -ForegroundColor Green
            Write-Host "[!] A reboot is REQUIRED before continuing." -ForegroundColor Yellow
            Write-Host "    Re-run this script after reboot." -ForegroundColor Yellow
            Restart-Computer -Force
            return
        }
        catch {
            Write-Host "ERROR: Failed to rename computer." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            return
        }
    }
}

#----------------------------#
# 1) Install Roles (optional)
#----------------------------#
if (Prompt-YesNo "Install AD DS, DNS, and DHCP roles on this server?") {
    Write-Host "[*] Installing AD-Domain-Services, DNS, and DHCP Server roles..." -ForegroundColor Cyan
    try {
        Install-WindowsFeature -Name AD-Domain-Services, DNS, DHCP -IncludeManagementTools | Out-Null
        Write-Host "[+] Roles installed (or already present)." -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Failed to install one or more roles." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host "TROUBLESHOOT:" -ForegroundColor Yellow
        Write-Host " - Make sure this is Windows Server, not a client OS." -ForegroundColor Yellow
        Write-Host " - Check Server Manager to see if roles are partially installed." -ForegroundColor Yellow
    }
    Write-Host ""
}
#-----------------------------------------#
# Force compliant local Administrator password 
#-----------------------------------------#
if (-not $IsDC) {

    Write-Host ""
    Write-Host "=== Setting local Administrator password (exam preset) ===" -ForegroundColor Cyan

    # 1. DISABLE PASSWORD COMPLEXITY REQUIREMENTS (Prevents the error)
    Write-Host "[*] Disabling Password Complexity Requirements..." -ForegroundColor Cyan
    $SecEditConfig = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $SecEditConfig | Out-Null
    (Get-Content $SecEditConfig) -replace "PasswordComplexity = 1", "PasswordComplexity = 0" | Set-Content $SecEditConfig
    (Get-Content $SecEditConfig) -replace "MinimumPasswordLength = .*", "MinimumPasswordLength = 0" | Set-Content $SecEditConfig
    secedit /configure /db secedit.sdb /cfg $SecEditConfig /areas SECURITYPOLICY | Out-Null

    # 2. SET THE PASSWORD
    $PlainAdminPassword = "student" 
    try {
        Write-Host "[*] Updating local Administrator password..." -ForegroundColor Cyan
        cmd.exe /c "net user Administrator $PlainAdminPassword"
        Write-Host "[+] Local Administrator password set successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Failed to set local Administrator password." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return
    }

    Write-Host "[!] Administrator password is now: $PlainAdminPassword" -ForegroundColor Yellow
    Write-Host ""
}

#-----------------------------------------#
# 2) Promote server to a new forest (opt) #
#-----------------------------------------#
if (-not $IsDC -and (Prompt-YesNo "Promote this server to a NEW forest/domain ($DomainName)? (This will eventually reboot)")) {
    try {
        Import-Module ADDSDeployment -ErrorAction Stop

        $dsrmPwd = Read-Host "Enter DSRM (Directory Services Restore Mode) password" -AsSecureString

        Write-Host "[*] Promoting server to domain controller for $DomainName ..." -ForegroundColor Cyan
        Write-Host "    This may take several minutes and will reboot at the end." -ForegroundColor Yellow

        # NOTE: Not passing DomainNetbiosName to avoid parameter issues on some builds.
        Install-ADDSForest `
            -DomainName $DomainName `
            -SafeModeAdministratorPassword $dsrmPwd `
            -InstallDNS `
            -Force

        Write-Host "[!] The server will reboot after promotion. Re-run this script afterwards for DHCP/OUs/users/GPOs." -ForegroundColor Yellow
        return
    }
    catch {
        Write-Host "ERROR during domain promotion:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host "TROUBLESHOOT:" -ForegroundColor Yellow
        Write-Host " - Make sure this server has a STATIC IP." -ForegroundColor Yellow
        Write-Host " - Preferred DNS on this NIC should be this server's own IP." -ForegroundColor Yellow
        Write-Host " - Check that no other DC for '$DomainName' already exists on the network." -ForegroundColor Yellow
        Write-Host " - If this partially promoted, re-image is usually faster for an exam." -ForegroundColor Yellow
        return
    }
}

# From this point down we assume we are on a DC (either originally or after reboot+rerun).

#---------------------------------#
# 3) Configure DHCP (optional)    #
#---------------------------------#
if (Prompt-YesNo "Configure DHCP scope, exclusions, and options?") {
    try {
        Import-Module DhcpServer -ErrorAction Stop
    }
    catch {
        Write-Host "ERROR: DhcpServer PowerShell module not available. Is the DHCP role installed?" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host "TROUBLESHOOT:" -ForegroundColor Yellow
        Write-Host " - Make sure you answered Y to install DHCP, or install via Server Manager." -ForegroundColor Yellow
        Write-Host " - You can still continue with AD/OUs/users/GPOs without DHCP." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "=== DHCP Server Configuration ===" -ForegroundColor Cyan

    $ServerIP       = Read-Host "Enter this server's STATIC IPv4 address (e.g. 192.168.10.10)"
    $ScopeNetworkID = Read-Host "Enter network ID for the scope (e.g. 192.168.10.0)"
    $ScopeName      = Read-Host "Enter a name for the DHCP scope (e.g. LabScope)"
    $ScopeStart     = Read-Host "Enter FIRST dynamic IP (e.g. 192.168.10.11)"
    $ScopeEnd       = Read-Host "Enter LAST dynamic IP  (e.g. 192.168.10.253)"
    $SubnetMask     = Read-Host "Enter subnet mask (e.g. 255.255.255.0)"

    # Authorize DHCP server in AD if needed
    if (-not (Get-DhcpServerInDC -ErrorAction SilentlyContinue | Where-Object { $_.IpAddress -eq $ServerIP })) {
        Write-Host "[*] Authorizing this DHCP server in Active Directory..." -ForegroundColor Cyan
        try {
            Add-DhcpServerInDC -DnsName $env:COMPUTERNAME -IpAddress $ServerIP
            Write-Host "[+] DHCP server authorized in AD." -ForegroundColor Green
        }
        catch {
            Write-Host "ERROR: Failed to authorize DHCP server in AD." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            Write-Host "TROUBLESHOOT:" -ForegroundColor Yellow
            Write-Host " - Ensure this server is a DC and can contact a writable domain controller." -ForegroundColor Yellow
            Write-Host " - Check network connectivity and DNS." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[!] DHCP server already authorized in AD; skipping authorization." -ForegroundColor Yellow
    }

    # Create scope if not present
    if (-not (Get-DhcpServerv4Scope -ScopeId $ScopeNetworkID -ErrorAction SilentlyContinue)) {
        Write-Host "[*] Creating DHCP scope '$ScopeName' ($ScopeStart - $ScopeEnd)..." -ForegroundColor Cyan
        try {
            New-DhcpServerv4Scope `
                -Name $ScopeName `
                -StartRange $ScopeStart `
                -EndRange $ScopeEnd `
                -SubnetMask $SubnetMask `
                -ScopeId $ScopeNetworkID `
                -State Active | Out-Null

            Write-Host "[+] Scope created and activated." -ForegroundColor Green
        }
        catch {
            Write-Host "ERROR: Failed to create DHCP scope." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            Write-Host "TROUBLESHOOT:" -ForegroundColor Yellow
            Write-Host " - Make sure ScopeId is the NETWORK ID (e.g. 192.168.10.0), not the server IP." -ForegroundColor Yellow
            Write-Host " - Ensure Start/End IPs are within the same subnet and in correct order." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[!] Scope with ScopeId $ScopeNetworkID already exists; skipping creation." -ForegroundColor Yellow
    }

    # Exclusion ranges for statics
    if (Prompt-YesNo "Configure one or more EXCLUSION ranges for static IPs (gateway/servers)?") {
        $more = $true
        while ($more) {
            $ExStart = Read-Host "  Exclusion START IP (e.g. 192.168.10.1)"
            $ExEnd   = Read-Host "  Exclusion END IP   (e.g. 192.168.10.10)"
            Write-Host "  [*] Adding exclusion range $ExStart - $ExEnd ..." -ForegroundColor Cyan

            try {
                # Optional sanity check: exclusion inside scope
                if (([ipaddress]$ExStart).Address -lt ([ipaddress]$ScopeStart).Address -or
                    ([ipaddress]$ExEnd).Address   -gt ([ipaddress]$ScopeEnd).Address) {

                    Write-Host "  ERROR: Exclusion range is outside the scope range. Skipping." -ForegroundColor Red
                    Write-Host "  TROUBLESHOOT: Make sure exclusions are within $ScopeStart - $ScopeEnd." -ForegroundColor Yellow
                }
                else {
                    Add-DhcpServerv4ExclusionRange `
                        -ScopeId $ScopeNetworkID `
                        -StartRange $ExStart `
                        -EndRange $ExEnd
                    Write-Host "  [+] Exclusion range added." -ForegroundColor Green
                }
            }
            catch {
                Write-Host "  ERROR: Failed to add exclusion range." -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                Write-Host "  TROUBLESHOOT: Check that the exclusion range does not overlap with other exclusions." -ForegroundColor Yellow
            }

            $more = Prompt-YesNo "  Add another exclusion range?"
        }
    }
    else {
        Write-Host "[!] No exclusion ranges configured. DHCP may assign ALL addresses in the scope." -ForegroundColor Yellow
    }

    # Scope options: gateway + DNS + domain name
    $Gateway      = Read-Host "Enter default gateway IP (pfSense LAN, etc. e.g. 192.168.10.254)"
    $PrimaryDNS   = Read-Host "Enter PRIMARY DNS server IP (usually this DC: $ServerIP)"
    $SecondaryDNS = Read-Host "Enter SECONDARY DNS server IP (optional, blank to skip)"

    $DnsServers = @()
    if (-not [string]::IsNullOrWhiteSpace($PrimaryDNS))   { $DnsServers += $PrimaryDNS }
    if (-not [string]::IsNullOrWhiteSpace($SecondaryDNS)) { $DnsServers += $SecondaryDNS }

    Write-Host "[*] Setting DHCP scope options (router/DNS/domain)..." -ForegroundColor Cyan
    try {
        Set-DhcpServerv4OptionValue `
            -ScopeId   $ScopeNetworkID `
            -Router    $Gateway `
            -DnsServer $DnsServers `
            -DnsDomain $DomainName
        Write-Host "[+] DHCP configuration complete." -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR while setting DHCP options." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host "TROUBLESHOOT:" -ForegroundColor Yellow
        Write-Host " - Verify ScopeId, gateway, and DNS IPs are valid and in the correct subnet." -ForegroundColor Yellow
        Write-Host " - Make sure the DHCP scope actually exists and is Active." -ForegroundColor Yellow
    }

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
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "TROUBLESHOOT:" -ForegroundColor Yellow
    Write-Host " - Make sure this server is a DC and AD DS role is installed." -ForegroundColor Yellow
    Write-Host " - If you just promoted to DC, reboot and rerun this script." -ForegroundColor Yellow
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
            try {
                New-ADOrganizationalUnit `
                    -Name $ouName `
                    -Path $DomainDN `
                    -ProtectedFromAccidentalDeletion $true | Out-Null
                Write-Host "[+] OU '$ouName' created." -ForegroundColor Green
            }
            catch {
                Write-Host "ERROR: Failed to create OU '$ouName'." -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                Write-Host "TROUBLESHOOT:" -ForegroundColor Yellow
                Write-Host " - Ensure the DN '$DomainDN' is correct." -ForegroundColor Yellow
                Write-Host " - Check for typos in the OU name." -ForegroundColor Yellow
            }
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
        Write-Host "TROUBLESHOOT: Double-check the OU name matches exactly what you created." -ForegroundColor Yellow
    }
    else {
        $BaseName    = Read-Host "Enter base username (e.g. 'user' => user1, user2...)"
        $StartIndex  = [int](Read-Host "Enter starting number (e.g. 1)"
        )
        $UserCount   = [int](Read-Host "How many users do you want to create?")
        $PasswordSec = Read-Host "Enter password for ALL created users" -AsSecureString

        $AddToGroup = $false
        $GroupName  = $null
        if (Prompt-YesNo "Add all of these users to an additional group (e.g. Domain Admins)?") {
            $GroupName  = Read-Host "Enter group name (e.g. 'Domain Admins' or a custom group)"
            $AddToGroup = $true
        }

        $usersCreated = @()
        for ($i = 0; $i -lt $UserCount; $i++) {
            $n    = $StartIndex + $i
            $sam  = "$BaseName$n"
            $upn  = "$sam@$DomainName"
            $name = $sam

            Write-Host "[*] Creating user '$sam' in $TargetOUPath ..." -ForegroundColor Cyan
            try {
                New-ADUser `
                    -Name $name `
                    -SamAccountName $sam `
                    -UserPrincipalName $upn `
                    -Path $TargetOUPath `
                    -AccountPassword $PasswordSec `
                    -Enabled $true `
                    -PasswordNeverExpires $true `
                    -ChangePasswordAtLogon $false `
                    -ErrorAction Stop | Out-Null

                $usersCreated += $sam
                Write-Host "[+] Created user $sam" -ForegroundColor Green
            }
            catch {
                Write-Host "[!] Could not create $sam (maybe already exists)." -ForegroundColor Yellow
                Write-Host $_.Exception.Message -ForegroundColor Yellow
                Write-Host "TROUBLESHOOT: Check for duplicate usernames, or invalid password complexity." -ForegroundColor Yellow
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
                    Write-Host "  [!] Failed to add $u to $GroupName." -ForegroundColor Yellow
                    Write-Host $_.Exception.Message -ForegroundColor Yellow
                    Write-Host "  TROUBLESHOOT: Ensure the group '$GroupName' exists and name is exact." -ForegroundColor Yellow
                }
            }
        }

        Write-Host "[+] Bulk user creation complete." -ForegroundColor Green
    }
    Write-Host ""
}

#---------------------------------#
# 5b) Single AD User Creation     #
#---------------------------------#
if (Prompt-YesNo "Create a single Active Directory user?") {

    Write-Host ""
    Write-Host "=== Single AD User Creation ===" -ForegroundColor Cyan

    # Username / Full name
    $UserName = Read-Host "Enter sAMAccountName (username)"
    $FullName = Read-Host "Enter full name for the user"

    # OU Input
    $OUInput = Read-Host "Enter FULL OU DN (e.g. OU=Weezer,$DomainDN)"

    if (-not (Get-ADOrganizationalUnit -Identity $OUInput -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: OU '$OUInput' not found. User creation aborted." -ForegroundColor Red
        Write-Host "TROUBLESHOOT: Copy the DN exactly from ADUC if needed (e.g. right-click OU → Properties)." -ForegroundColor Yellow
    }
    else {
        # Password
        $PasswordSec = Read-Host "Enter password for this user" -AsSecureString

        # Build UPN
        $UPN = "$UserName@$DomainName"

        Write-Host "[*] Creating AD user '$UserName' in '$OUInput'..." -ForegroundColor Cyan

        try {
            New-ADUser `
                -Name $FullName `
                -SamAccountName $UserName `
                -UserPrincipalName $UPN `
                -Path $OUInput `
                -AccountPassword $PasswordSec `
                -Enabled $true `
                -PasswordNeverExpires $false `
                -ChangePasswordAtLogon $false `
                -ErrorAction Stop

            Write-Host "[+] Successfully created user '$UserName'." -ForegroundColor Green
        }
        catch {
            Write-Host "[!] ERROR creating user '$UserName'." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            Write-Host "TROUBLESHOOT:" -ForegroundColor Yellow
            Write-Host " - Check password complexity rules." -ForegroundColor Yellow
            Write-Host " - Check for existing user with same sAMAccountName/UPN." -ForegroundColor Yellow
        }

        # Optional group membership
        if (Prompt-YesNo "Add this user to group(s)?") {
            $GroupList = Read-Host "Enter group names separated by commas"
            $Groups = $GroupList.Split(",") | ForEach-Object { $_.Trim() }

            foreach ($G in $Groups) {
                try {
                    Add-ADGroupMember -Identity $G -Members $UserName -ErrorAction Stop
                    Write-Host "  [+] Added '$UserName' to '$G'" -ForegroundColor Green
                }
                catch {
                    Write-Host "  [!] Could not add to group '$G'." -ForegroundColor Yellow
                    Write-Host $_.Exception.Message -ForegroundColor Yellow
                    Write-Host "  TROUBLESHOOT: Group name must be exact and exist in AD." -ForegroundColor Yellow
                }
            }
        }

        Write-Host "[+] Single-user creation complete." -ForegroundColor Green
        Write-Host ""
    }
}

#---------------------------------#
# 6) GPOs & links (optional)      #
#---------------------------------#
try {
    Import-Module GroupPolicy -ErrorAction Stop
}
catch {
    Write-Host "WARNING: GroupPolicy module not available. Skipping GPO section." -ForegroundColor Yellow
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Write-Host "TROUBLESHOOT: Make sure Group Policy Management features/RSAT are installed on this server." -ForegroundColor Yellow
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
        try {
            $gpo = New-GPO -Name $GpoName -Comment "Created by DC setup script to restrict Control Panel"
            Write-Host "[+] GPO '$GpoName' created." -ForegroundColor Green
        }
        catch {
            Write-Host "ERROR: Failed to create GPO '$GpoName'." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }
    else {
        Write-Host "[!] GPO '$GpoName' already exists; reusing." -ForegroundColor Yellow
    }

    Write-Host "[*] Linking GPO '$GpoName' to domain '$DomainName'..." -ForegroundColor Cyan
    try {
        New-GPLink -Name $GpoName -Target $DomainName -Enforced:$false -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Write-Host "ERROR: Failed to link GPO to domain." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host "TROUBLESHOOT: Ensure the domain FQDN '$DomainName' is correct." -ForegroundColor Yellow
    }

    # Configure NoControlPanel = 1 (HKCU)
    Write-Host "[*] Setting registry value to prohibit Control Panel access..." -ForegroundColor Cyan
    try {
        Set-GPRegistryValue `
            -Name $GpoName `
            -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
            -ValueName "NoControlPanel" `
            -Type DWord `
            -Value 1
        Write-Host "[+] GPO '$GpoName' configured and linked to domain." -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Failed to set registry value in GPO." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }

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
        Write-Host "TROUBLESHOOT: Verify the OU name is correct and exists." -ForegroundColor Yellow
    }
    else {
        $WallpaperPath = Read-Host "Enter UNC path to wallpaper image (e.g. \\SERVER\Share\wallpaper.jpg)"
        $Style = Read-Host "Enter wallpaper style number (0=Center, 2=Stretch) [default 2]"
        if ([string]::IsNullOrWhiteSpace($Style)) { $Style = "2" }

        $gpo2 = Get-GPO -Name $GpoName2 -ErrorAction SilentlyContinue
        if (-not $gpo2) {
            Write-Host "[*] Creating GPO '$GpoName2'..." -ForegroundColor Cyan
            try {
                $gpo2 = New-GPO -Name $GpoName2 -Comment "Created by DC setup script for OU wallpaper"
                Write-Host "[+] GPO '$GpoName2' created." -ForegroundColor Green
            }
            catch {
                Write-Host "ERROR: Failed to create wallpaper GPO." -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
            }
        }
        else {
            Write-Host "[!] GPO '$GpoName2' already exists; reusing." -ForegroundColor Yellow
        }

        Write-Host "[*] Linking GPO '$GpoName2' to OU '$TargetOUDN2'..." -ForegroundColor Cyan
        try {
            New-GPLink -Name $GpoName2 -Target $TargetOUDN2 -Enforced:$false -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Host "ERROR: Failed to link wallpaper GPO to OU." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }

        # Configure wallpaper settings
        Write-Host "[*] Setting wallpaper registry values in GPO..." -ForegroundColor Cyan
        try {
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
            Write-Host "    Remember to run 'gpupdate /force' on a client in that OU." -ForegroundColor Yellow
        }
        catch {
            Write-Host "ERROR: Failed to set wallpaper registry values in GPO." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }
}

#---------------------------------#
# 7) DNS Record Management (A/CNAME/PTR)
#---------------------------------#
if (Prompt-YesNo "Create DNS A, CNAME, and/or PTR records for domain-joined computers?") {

    Write-Host ""
    Write-Host "=== DNS Record Management ===" -ForegroundColor Cyan
    try {
        Import-Module DnsServer -ErrorAction Stop
    }
    catch {
        Write-Host "ERROR: DnsServer module not available. Is the DNS role installed?" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host "TROUBLESHOOT: DNS role must be installed on this server to manage zones/records." -ForegroundColor Yellow
        return
    }

    # Ask how many records to create
    $RecordCount = [int](Read-Host "How many computer DNS records would you like to create?")

    for ($i = 1; $i -le $RecordCount; $i++) {

        Write-Host ""
        Write-Host "=== Record $i ===" -ForegroundColor Cyan

        # Basic info
        $Hostname = Read-Host "Enter HOSTNAME (e.g., client1)"
        $IPv4     = Read-Host "Enter IPv4 address for $Hostname"

        # Validate forward zone
        if (-not (Get-DnsServerZone -Name $DomainName -ErrorAction SilentlyContinue)) {
            Write-Host "ERROR: Forward lookup zone '$DomainName' does not exist." -ForegroundColor Red
            Write-Host "TROUBLESHOOT: Check DNS Manager to confirm the zone name matches your domain." -ForegroundColor Yellow
            continue
        }

        #--------------------------------------------#
        # Create A Record
        #--------------------------------------------#
        if (Prompt-YesNo "Create A record for $Hostname.$DomainName → $IPv4 ?") {
            try {
                # Optional: skip if already exists
                $existingA = Get-DnsServerResourceRecord -ZoneName $DomainName -Name $Hostname -ErrorAction SilentlyContinue
                if ($existingA) {
                    Write-Host "[!] A record for $Hostname already exists; skipping." -ForegroundColor Yellow
                }
                else {
                    Add-DnsServerResourceRecordA `
                        -Name $Hostname `
                        -ZoneName $DomainName `
                        -IPv4Address $IPv4 `
                        -ErrorAction Stop

                    Write-Host "[+] A record created: $Hostname.$DomainName → $IPv4" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "[!] Failed to create A record." -ForegroundColor Yellow
                Write-Host $_.Exception.Message -ForegroundColor Yellow
                Write-Host "TROUBLESHOOT: Check IP format and that the name is not already in use." -ForegroundColor Yellow
            }
        }

        #--------------------------------------------#
        # Create CNAME
        #--------------------------------------------#
        if (Prompt-YesNo "Create CNAME alias for this host?") {
            $Alias = Read-Host "Enter alias (e.g., www, fileserver, ssh)"
            try {
                Add-DnsServerResourceRecordCName `
                    -Name $Alias `
                    -HostNameAlias "$Hostname.$DomainName" `
                    -ZoneName $DomainName `
                    -ErrorAction Stop

                Write-Host "[+] CNAME created: $Alias.$DomainName → $Hostname.$DomainName" -ForegroundColor Green
            }
            catch {
                Write-Host "[!] Failed to create CNAME." -ForegroundColor Yellow
                Write-Host $_.Exception.Message -ForegroundColor Yellow
                Write-Host "TROUBLESHOOT: Make sure the alias name is not already an existing A record." -ForegroundColor Yellow
            }
        }

        #--------------------------------------------#
        # Create PTR (reverse lookup)
        #--------------------------------------------#
        if (Prompt-YesNo "Create PTR (reverse) record for $IPv4 ?") {

            # Auto-generate zone name based on IP (x.y.z.in-addr.arpa)
            $ipParts = $IPv4.Split(".")
            if ($ipParts.Count -ne 4) {
                Write-Host "ERROR: IPv4 address format invalid. Skipping PTR." -ForegroundColor Red
                continue
            }

            $ReverseZone = "$($ipParts[2]).$($ipParts[1]).$($ipParts[0]).in-addr.arpa"

            # Check for reverse zone
            if (-not (Get-DnsServerZone -Name $ReverseZone -ErrorAction SilentlyContinue)) {
                Write-Host "[!] Reverse zone '$ReverseZone' does not exist." -ForegroundColor Yellow

                if (Prompt-YesNo "Create reverse lookup zone $ReverseZone ?") {
                    try {
                        Add-DnsServerPrimaryZone `
                            -NetworkId "$($ipParts[0]).$($ipParts[1]).$($ipParts[2])" `
                            -PrefixLength 24 `
                            -ReplicationScope "Forest" `
                            -ErrorAction Stop

                        Write-Host "[+] Reverse zone created: $ReverseZone" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "[!] Failed to create reverse zone." -ForegroundColor Red
                        Write-Host $_.Exception.Message -ForegroundColor Red
                        Write-Host "TROUBLESHOOT: Check that the network ID is correct (e.g. 192.168.10)." -ForegroundColor Yellow
                        continue
                    }
                }
                else {
                    Write-Host "[!] Skipping PTR record (zone missing)." -ForegroundColor Yellow
                    continue
                }
            }

            $PTRName = $ipParts[3]   # last octet

            try {
                Add-DnsServerResourceRecordPtr `
                    -Name $PTRName `
                    -ZoneName $ReverseZone `
                    -PtrDomainName "$Hostname.$DomainName" `
                    -ErrorAction Stop

                Write-Host "[+] PTR created: $IPv4 → $Hostname.$DomainName" -ForegroundColor Green
            }
            catch {
                Write-Host "[!] Failed to create PTR." -ForegroundColor Yellow
                Write-Host $_.Exception.Message -ForegroundColor Yellow
                Write-Host "TROUBLESHOOT: Make sure no conflicting PTR already exists for this IP." -ForegroundColor Yellow
            }
        }
    }

    Write-Host ""
    Write-Host "[+] DNS record management complete." -ForegroundColor Green
}

#---------------------------------#
# 8) Mail Server Setup (MailEnable)
#---------------------------------#
if (Prompt-YesNo "Install & Configure MailEnable (Email Server)?") {

    # --- Variables ---
    $DomainName    = "bmw7216.com"
    $ServerIP      = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress[0]
    $IISRoot       = "C:\inetpub\wwwroot"
    $AutoConfigDir = "$IISRoot\mail"
    $MEName        = "MailEnable-Standard"
    $MEDownloadUrl = "https://www.mailenable.com/standard/MailEnable-Standard.exe"
    $MEInstaller   = "$env:TEMP\$MEName.exe"
    $MEInstallDir  = "C:\Program Files (x86)\Mail Enable"
    $MEBin         = "$MEInstallDir\Bin"

    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   MAIL SERVER AUTOMATION: DNS, IIS, & MailEnable Setup" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    # ------------------------------------------------------------------
    # STEP 1: DNS RECORDS
    # ------------------------------------------------------------------
    Write-Host "`n[1] Configuring DNS Records..." -ForegroundColor Cyan
    try {
        Add-DnsServerResourceRecordMX -Name "." -ZoneName $DomainName -MailExchange "mail.$DomainName" -Preference 10 -ErrorAction Stop
        Write-Host "    [+] MX Record created." -ForegroundColor Green
    } catch { Write-Host "    [!] MX Record exists." -ForegroundColor Yellow }

    try {
        Add-DnsServerResourceRecordA -Name "mail" -ZoneName $DomainName -IPv4Address $ServerIP -ErrorAction Stop
        Write-Host "    [+] 'mail' A Record created." -ForegroundColor Green
    } catch { Write-Host "    [!] 'mail' A Record exists." -ForegroundColor Yellow }

    try {
        Add-DnsServerResourceRecordA -Name "autoconfig" -ZoneName $DomainName -IPv4Address $ServerIP -ErrorAction Stop
        Write-Host "    [+] 'autoconfig' A Record created." -ForegroundColor Green
    } catch { Write-Host "    [!] 'autoconfig' A Record exists." -ForegroundColor Yellow }

    # ------------------------------------------------------------------
    # STEP 2: INSTALL MAILENABLE STANDARD (ROBUST)
    # ------------------------------------------------------------------
    Write-Host "`n[2] Installing MailEnable Standard..." -ForegroundColor Cyan

    if (-not (Test-Path "$MEBin\MEAdmin.exe")) {
        
        # 2a. Download with curl.exe (Bypasses IE Security)
        Write-Host "    [*] Downloading MailEnable installer via curl.exe..."
        
        # Clean up previous failed attempts
        if (Test-Path $MEInstaller) { Remove-Item $MEInstaller -Force }

        # We use '& curl.exe' to force PowerShell to use the actual .exe, not its own alias.
        # -L follows redirects
        # -o saves to file
        # -A spoofs a browser User-Agent to avoid 403 blocks
        & curl.exe -L -o "$MEInstaller" "$MEDownloadUrl" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

        # 2b. Validate Download
        if ((Test-Path $MEInstaller) -and (Get-Item $MEInstaller).Length -gt 50000000) {
            Write-Host "    [+] Download successful ($([math]::Round((Get-Item $MEInstaller).Length / 1MB, 2)) MB)." -ForegroundColor Green
        }
        else {
            Write-Host "    [!] curl failed. Attempting 'Nuclear Option' (Disabling IE Security)..." -ForegroundColor Yellow

            # --- NUCLEAR OPTION: Temporarily Disable IE ESC in Registry ---
            $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            $UserKey  = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            
            # Save current state so we can restore it (Good practice)
            $AdminState = (Get-ItemProperty -Path $AdminKey -Name "IsInstalled" -ErrorAction SilentlyContinue).IsInstalled
            $UserState  = (Get-ItemProperty -Path $UserKey -Name "IsInstalled" -ErrorAction SilentlyContinue).IsInstalled

            # Turn it OFF (0)
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $UserKey  -Name "IsInstalled" -Value 0 -ErrorAction SilentlyContinue
            
            try {
                # Try standard download again now that shields are down
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $MEDownloadUrl -OutFile $MEInstaller -UseBasicParsing
            }
            finally {
                # Turn it back ON (Restore state)
                if ($AdminState -ne $null) { Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value $AdminState }
                if ($UserState -ne $null)  { Set-ItemProperty -Path $UserKey  -Name "IsInstalled" -Value $UserState }
            }

            # Final Check
            if ((Get-Item $MEInstaller).Length -lt 50000000) {
                Write-Host "    [ERROR] Download STILL failed. You must download it manually." -ForegroundColor Red
                return
            }
        }

        # 2b. Install Silently
        Write-Host "    [*] Running Silent Installer (This takes 1-2 minutes)..."
        $Process = Start-Process -FilePath $MEInstaller -ArgumentList "/S" -PassThru
        $Process.WaitForExit()
        
        Write-Host "    [+] Installer finished." -ForegroundColor Green
        
        # 2c. Wait for Service Registration
        Write-Host "    [*] Waiting for system registration..."
        Start-Sleep -Seconds 20

        # 2d. Force Register COM Libraries (The most common failure point)
        if (Test-Path "$MEBin\MEInstaller.exe") {
             Write-Host "    [*] Registering MailEnable Components..."
             # Command '1' registers components in MEInstaller.exe
             Start-Process -FilePath "$MEBin\MEInstaller.exe" -ArgumentList "1" -Wait -WindowStyle Hidden
        }
    } else {
        Write-Host "    [!] MailEnable is already installed. Skipping install." -ForegroundColor Yellow
    }

    # ------------------------------------------------------------------
    # STEP 3: CONFIGURE POSTOFFICE & USER (via COM API)
    # ------------------------------------------------------------------
    Write-Host "`n[3] Creating Postoffice and Users..." -ForegroundColor Cyan

    # Define Functions
    function New-MEPostOffice {
        param($POName, $Password)
        try {
            $oPO = New-Object -ComObject MEAOPO.Postoffice
            $oPO.Name = $POName
            $oPO.Status = 1
            $oPO.Account = $POName
            if ($oPO.AddPostoffice() -eq 1) { 
                Write-Host "    [+] Postoffice '$POName' created." -ForegroundColor Green 
            } else { 
                Write-Host "    [!] Postoffice '$POName' likely exists." -ForegroundColor Yellow 
            }

            $oDom = New-Object -ComObject MEAOPO.Domain
            $oDom.AccountName = $POName
            $oDom.DomainName = $POName
            $oDom.Status = 1
            $oDom.AddDomain() | Out-Null
        } catch {
            Write-Host "    [ERROR] COM Object Failure. MailEnable libraries not registered." -ForegroundColor Red
            throw
        }
    }

    function New-MEMailbox {
        param($POName, $MailboxName, $Password)
        $oMbox = New-Object -ComObject MEAOPO.Mailbox
        $oMbox.Postoffice = $POName
        $oMbox.Mailbox = $MailboxName
        $oMbox.Limit = -1
        $oMbox.Status = 1
        $oMbox.AddMailbox() | Out-Null

        $oLogin = New-Object -ComObject MEAOPO.Login
        $oLogin.Account = $POName
        $oLogin.Password = $Password
        $oLogin.Rights = "USER"
        $oLogin.Status = 1
        $oLogin.UserName = "$MailboxName@$POName"
        $oLogin.AddLogin() | Out-Null

        $oMap = New-Object -ComObject MEAOPO.AddressMap
        $oMap.Account = $POName
        $oMap.DestinationAddress = "[SF:$POName/$MailboxName]"
        $oMap.SourceAddress = "[SMTP:$MailboxName@$POName]"
        $oMap.AddAddressMap() | Out-Null
        
        Write-Host "    [+] User '$MailboxName@$POName' created." -ForegroundColor Green
    }

    # Execute
    try {
        New-MEPostOffice -POName $DomainName -Password "P@ssword123"
        New-MEMailbox -POName $DomainName -MailboxName "student" -Password "student"
    }
    catch {
        Write-Host "    [ERROR] Configuration failed. Steps to fix:" -ForegroundColor Red
        Write-Host "    1. Open 'MailEnable Installer' from Start Menu." -ForegroundColor Yellow
        Write-Host "    2. Select 'Common Installation' -> 'Register Components' -> Execute." -ForegroundColor Yellow
        Write-Host "    3. Re-run this script." -ForegroundColor Yellow
    }

    # ------------------------------------------------------------------
    # STEP 4: IIS AUTOCONFIG
    # ------------------------------------------------------------------
    Write-Host "`n[4] Configuring IIS Autoconfig Service..." -ForegroundColor Cyan

    if (-not (Get-WindowsFeature Web-Server).Installed) {
        Install-WindowsFeature Web-Server -IncludeManagementTools | Out-Null
    }

    New-Item -Path $AutoConfigDir -ItemType Directory -Force | Out-Null

    $XmlContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="$DomainName">
    <domain>$DomainName</domain>
    <displayName>Juche Mail</displayName>
    <displayShortName>Juche</displayShortName>
    <incomingServer type="imap">
      <hostname>mail.$DomainName</hostname>
      <port>143</port>
      <socketType>plain</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>mail.$DomainName</hostname>
      <port>25</port>
      <socketType>plain</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
"@

    $XmlPath = "$AutoConfigDir\config-v1.1.xml"
    Set-Content -Path $XmlPath -Value $XmlContent
    Write-Host "    [+] XML config written to $XmlPath" -ForegroundColor Green

    # Restart IIS to apply changes
    IISReset /noforce | Out-Null
    Write-Host "    [+] IIS Restarted." -ForegroundColor Green

    Write-Host "`n[SUCCESS] Mail Server Setup Complete." -ForegroundColor Green
    Write-Host "           Postoffice: $DomainName" -ForegroundColor Gray
    Write-Host "           User:       student@$DomainName" -ForegroundColor Gray
    Write-Host "           Password:   student" -ForegroundColor Gray
    Write-Host ""
}


Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " All selected domain controller tasks have completed." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
