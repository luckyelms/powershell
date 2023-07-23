<#
    Ver: 1.2
    WareHouse
    Tasks:
        1. configure ssh
        2. setup DNS
        3. configure ansible access
    This file supercedes previous settings using winrm feature.
	$ErrorActionPreference = "continue"
	set-executionpolicy -ExecutionPolicy RemoteSigned
    Status: in-progress...
	Logs:
     - 29.06.23@1031: This snippet supercedes awx.ps1 & attempts to solve OpenSSH.Server installation failure.
    2DO:
        - Change Network from Public to Private
        
#>

#################################### configure for ansible ###############################################################
[CmdletBinding()]

Param (
    [string]$SubjectName = $env:COMPUTERNAME,
    [int]$CertValidityDays = 1095,
    [switch]$SkipNetworkProfileCheck,
    $CreateSelfSignedCert = $true,
    [switch]$ForceNewSSLCert,
    [switch]$GlobalHttpFirewallAccess,
    [switch]$DisableBasicAuth = $false,
    [switch]$EnableCredSSP
)

Function Write-ProgressLog {
    $Message = $args[0]
    Write-EventLog -LogName Application -Source $EventSource -EntryType Information -EventId 1 -Message $Message
}

Function Write-VerboseLog {
    $Message = $args[0]
    Write-Verbose $Message
    Write-ProgressLog $Message
}

Function Write-HostLog {
    $Message = $args[0]
    Write-Output $Message
    Write-ProgressLog $Message
}

Function New-LegacySelfSignedCert {
    Param (
        [string]$SubjectName,
        [int]$ValidDays = 1095
    )

    $hostnonFQDN = $env:computerName
    $hostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname
    $SignatureAlgorithm = "SHA256"

    $name = New-Object -COM "X509Enrollment.CX500DistinguishedName.1"
    $name.Encode("CN=$SubjectName", 0)

    $key = New-Object -COM "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    $key.KeySpec = 1
    $key.Length = 4096
    $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $key.MachineContext = 1
    $key.Create()

    $serverauthoid = New-Object -COM "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuoids = New-Object -COM "X509Enrollment.CObjectIds.1"
    $ekuoids.Add($serverauthoid)
    $ekuext = New-Object -COM "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
    $ekuext.InitializeEncode($ekuoids)

    $cert = New-Object -COM "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey(2, $key, "")
    $cert.Subject = $name
    $cert.Issuer = $cert.Subject
    $cert.NotBefore = (Get-Date).AddDays(-1)
    $cert.NotAfter = $cert.NotBefore.AddDays($ValidDays)

    $SigOID = New-Object -ComObject X509Enrollment.CObjectId
    $SigOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)

    [string[]] $AlternativeName += $hostnonFQDN
    $AlternativeName += $hostFQDN
    $IAlternativeNames = New-Object -ComObject X509Enrollment.CAlternativeNames

    foreach ($AN in $AlternativeName) {
        $AltName = New-Object -ComObject X509Enrollment.CAlternativeName
        $AltName.InitializeFromString(0x3, $AN)
        $IAlternativeNames.Add($AltName)
    }

    $SubjectAlternativeName = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $SubjectAlternativeName.InitializeEncode($IAlternativeNames)

    [String[]]$KeyUsage = ("DigitalSignature", "KeyEncipherment")
    $KeyUsageObj = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
    $KeyUsageObj.InitializeEncode([int][Security.Cryptography.X509Certificates.X509KeyUsageFlags]($KeyUsage))
    $KeyUsageObj.Critical = $true

    $cert.X509Extensions.Add($KeyUsageObj)
    $cert.X509Extensions.Add($ekuext)
    $cert.SignatureInformation.HashAlgorithm = $SigOID
    $CERT.X509Extensions.Add($SubjectAlternativeName)
    $cert.Encode()

    $enrollment = New-Object -COM "X509Enrollment.CX509Enrollment.1"
    $enrollment.InitializeFromRequest($cert)
    $certdata = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certdata, 0, "")

    # extract/return the thumbprint from the generated cert
    $parsed_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $parsed_cert.Import([System.Text.Encoding]::UTF8.GetBytes($certdata))

    return $parsed_cert.Thumbprint
}

Function Enable-GlobalHttpFirewallAccess {
    Write-Verbose "Forcing global HTTP firewall access"
    # this is a fairly naive implementation; could be more sophisticated about rule matching/collapsing
    $fw = New-Object -ComObject HNetCfg.FWPolicy2

    # try to find/enable the default rule first
    $add_rule = $false
    $matching_rules = $fw.Rules | Where-Object { $_.Name -eq "Windows Remote Management (HTTP-In)" }
    $rule = $null
    If ($matching_rules) {
        If ($matching_rules -isnot [Array]) {
            Write-Verbose "Editing existing single HTTP firewall rule"
            $rule = $matching_rules
        }
        Else {
            # try to find one with the All or Public profile first
            Write-Verbose "Found multiple existing HTTP firewall rules..."
            $rule = $matching_rules | ForEach-Object { $_.Profiles -band 4 }[0]

            If (-not $rule -or $rule -is [Array]) {
                Write-Verbose "Editing an arbitrary single HTTP firewall rule (multiple existed)"
                # oh well, just pick the first one
                $rule = $matching_rules[0]
            }
        }
    }

    If (-not $rule) {
        Write-Verbose "Creating a new HTTP firewall rule"
        $rule = New-Object -ComObject HNetCfg.FWRule
        $rule.Name = "Windows Remote Management (HTTP-In)"
        $rule.Description = "Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]"
        $add_rule = $true
    }

    $rule.Profiles = 0x7FFFFFFF
    $rule.Protocol = 6
    $rule.LocalPorts = 5985
    $rule.RemotePorts = "*"
    $rule.LocalAddresses = "*"
    $rule.RemoteAddresses = "*"
    $rule.Enabled = $true
    $rule.Direction = 1
    $rule.Action = 1
    $rule.Grouping = "Windows Remote Management"

    If ($add_rule) {
        $fw.Rules.Add($rule)
    }

    Write-Verbose "HTTP firewall rule $($rule.Name) updated"
}

# Setup error handling.
Trap {
    $_
    Exit 1
}
$ErrorActionPreference = "Stop"

# Get the ID and security principal of the current user account
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

# Get the security principal for the Administrator role
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

# Check to see if we are currently running "as Administrator"
if (-Not $myWindowsPrincipal.IsInRole($adminRole)) {
    Write-Output "ERROR: You need elevated Administrator privileges in order to run this script."
    Write-Output "       Start Windows PowerShell by using the Run as Administrator option."
    Exit 2
}

$EventSource = $MyInvocation.MyCommand.Name
If (-Not $EventSource) {
    $EventSource = "Powershell CLI"
}

If ([System.Diagnostics.EventLog]::Exists('Application') -eq $False -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $False) {
    New-EventLog -LogName Application -Source $EventSource
}

# Detect PowerShell version.
If ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-ProgressLog "PowerShell version 3 or higher is required."
    Throw "PowerShell version 3 or higher is required."
}

# Find and start the WinRM service.
Write-Verbose "Verifying WinRM service."
If (!(Get-Service "WinRM")) {
    Write-ProgressLog "Unable to find the WinRM service."
    Throw "Unable to find the WinRM service."
}
ElseIf ((Get-Service "WinRM").Status -ne "Running") {
    Write-Verbose "Setting WinRM service to start automatically on boot."
    Set-Service -Name "WinRM" -StartupType Automatic
    Write-ProgressLog "Set WinRM service to start automatically on boot."
    Write-Verbose "Starting WinRM service."
    Start-Service -Name "WinRM" -ErrorAction Stop
    Write-ProgressLog "Started WinRM service."

}

# WinRM should be running; check that we have a PS session config.
If (!(Get-PSSessionConfiguration -Verbose:$false) -or (!(Get-ChildItem WSMan:\localhost\Listener))) {
    If ($SkipNetworkProfileCheck) {
        Write-Verbose "Enabling PS Remoting without checking Network profile."
        Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
        Write-ProgressLog "Enabled PS Remoting without checking Network profile."
    }
    Else {
        Write-Verbose "Enabling PS Remoting."
        Enable-PSRemoting -Force -ErrorAction Stop
        Write-ProgressLog "Enabled PS Remoting."
    }
}
Else {
    Write-Verbose "PS Remoting is already enabled."
}

# Ensure LocalAccountTokenFilterPolicy is set to 1
# https://github.com/ansible/ansible/issues/42978
$token_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$token_prop_name = "LocalAccountTokenFilterPolicy"
$token_key = Get-Item -Path $token_path
$token_value = $token_key.GetValue($token_prop_name, $null)
if ($token_value -ne 1) {
    Write-Verbose "Setting LocalAccountTOkenFilterPolicy to 1"
    if ($null -ne $token_value) {
        Remove-ItemProperty -Path $token_path -Name $token_prop_name
    }
    New-ItemProperty -Path $token_path -Name $token_prop_name -Value 1 -PropertyType DWORD > $null
}

# Make sure there is a SSL listener.
$listeners = Get-ChildItem WSMan:\localhost\Listener
If (!($listeners | Where-Object { $_.Keys -like "TRANSPORT=HTTPS" })) {
    # We cannot use New-SelfSignedCertificate on 2012R2 and earlier
    $thumbprint = New-LegacySelfSignedCert -SubjectName $SubjectName -ValidDays $CertValidityDays
    Write-HostLog "Self-signed SSL certificate generated; thumbprint: $thumbprint"

    # Create the hashtables of settings to be used.
    $valueset = @{
        Hostname = $SubjectName
        CertificateThumbprint = $thumbprint
    }

    $selectorset = @{
        Transport = "HTTPS"
        Address = "*"
    }

    Write-Verbose "Enabling SSL listener."
    New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
    Write-ProgressLog "Enabled SSL listener."
}
Else {
    Write-Verbose "SSL listener is already active."

    # Force a new SSL cert on Listener if the $ForceNewSSLCert
    If ($ForceNewSSLCert) {

        # We cannot use New-SelfSignedCertificate on 2012R2 and earlier
        $thumbprint = New-LegacySelfSignedCert -SubjectName $SubjectName -ValidDays $CertValidityDays
        Write-HostLog "Self-signed SSL certificate generated; thumbprint: $thumbprint"

        $valueset = @{
            CertificateThumbprint = $thumbprint
            Hostname = $SubjectName
        }

        # Delete the listener for SSL
        $selectorset = @{
            Address = "*"
            Transport = "HTTPS"
        }
        Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset

        # Add new Listener with new SSL cert
        New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
    }
}

# Check for basic authentication.
$basicAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where-Object { $_.Name -eq "Basic" }

If ($DisableBasicAuth) {
    If (($basicAuthSetting.Value) -eq $true) {
        Write-Verbose "Disabling basic auth support."
        Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $false
        Write-ProgressLog "Disabled basic auth support."
    }
    Else {
        Write-Verbose "Basic auth is already disabled."
    }
}
Else {
    If (($basicAuthSetting.Value) -eq $false) {
        Write-Verbose "Enabling basic auth support."
        Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
        Write-ProgressLog "Enabled basic auth support."
    }
    Else {
        Write-Verbose "Basic auth is already enabled."
    }
}

# If EnableCredSSP if set to true
If ($EnableCredSSP) {
    # Check for CredSSP authentication
    $credsspAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where-Object { $_.Name -eq "CredSSP" }
    If (($credsspAuthSetting.Value) -eq $false) {
        Write-Verbose "Enabling CredSSP auth support."
        Enable-WSManCredSSP -role server -Force
        Write-ProgressLog "Enabled CredSSP auth support."
    }
}

If ($GlobalHttpFirewallAccess) {
    Enable-GlobalHttpFirewallAccess
}

# Configure firewall to allow WinRM HTTPS connections.
$fwtest1 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS"
$fwtest2 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS" profile=any
If ($fwtest1.count -lt 5) {
    Write-Verbose "Adding firewall rule to allow WinRM HTTPS."
    netsh advfirewall firewall add rule profile=any name="Allow WinRM HTTPS" dir=in localport=5986 protocol=TCP action=allow
    Write-ProgressLog "Added firewall rule to allow WinRM HTTPS."
}
ElseIf (($fwtest1.count -ge 5) -and ($fwtest2.count -lt 5)) {
    Write-Verbose "Updating firewall rule to allow WinRM HTTPS for any profile."
    netsh advfirewall firewall set rule name="Allow WinRM HTTPS" new profile=any
    Write-ProgressLog "Updated firewall rule to allow WinRM HTTPS for any profile."
}
Else {
    Write-Verbose "Firewall rule already exists to allow WinRM HTTPS."
}

# Test a remoting connection to localhost, which should work.
$httpResult = Invoke-Command -ComputerName "localhost" -ScriptBlock { $using:env:COMPUTERNAME } -ErrorVariable httpError -ErrorAction SilentlyContinue
$httpsOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

$httpsResult = New-PSSession -UseSSL -ComputerName "localhost" -SessionOption $httpsOptions -ErrorVariable httpsError -ErrorAction SilentlyContinue

If ($httpResult -and $httpsResult) {
    Write-Verbose "HTTP: Enabled | HTTPS: Enabled"
}
ElseIf ($httpsResult -and !$httpResult) {
    Write-Verbose "HTTP: Disabled | HTTPS: Enabled"
}
ElseIf ($httpResult -and !$httpsResult) {
    Write-Verbose "HTTP: Enabled | HTTPS: Disabled"
}
Else {
    Write-ProgressLog "Unable to establish an HTTP or HTTPS remoting session."
    Throw "Unable to establish an HTTP or HTTPS remoting session."
}
Write-VerboseLog "PS Remoting has been successfully configured for Ansible."

#################################### END configure for ansible ###############################################################

# allow ICMP
netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow

# Install OenSSH
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Set service to automatic and start
Set-Service sshd -StartupType Automatic
Start-Service sshd

# Configure PowerShell as the default shell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

# Confirm the Firewall rule is configured. It should be created automatically by setup.
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}
# Restart the service
Restart-Service sshd

################################### END configure for ansible ###############################################################



################################### Set DNS ###############################################################
$wifiInterface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "Wi-Fi*" }

if ($wifiInterface) 
{
    # ---- Checking if on Jumia Wi-Fi, if not, do nothing
    $ssid = (netsh wlan show interfaces | Select-String 'SSID').Line.Split(':')[1].Trim()
    if ($ssid -like "Jumia-WH" -or $ssid -like "Jumia-WH2")
    {
        $adapterDetails = Get-NetAdapter -Name $wifiInterface.Name
        $dnsSuffix = (Get-DnsClientGlobalSetting).SuffixSearchList
        
        # Get the DNS IPs
        $dnsServers = $adapterDetails | Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses

        # Get the mac address:
        $macAddress = $wifiInterface.MacAddress
        $macAddress = $macAddress.Replace("-", ":")
        # host Name
        $hostName = hostname
        
        # Testing ...
        <##>
            Write-Output "Connected Wi-Fi network (SSID): $ssid"
            Write-Output "Network Adapter: $($adapterDetails.Name)"
            Write-Output "DNS Suffix: $dnsSuffix"
            Write-Output "DNS Servers: $dnsServers"
            Write-Output "Mac Address: $macAddress"
            Write-Output "Host Name: $hostName"
        
        
        # Log Data:
        $dat = Get-Date
        $formattedDate = $dat.ToString("dd-MM-yy HH:mm:ss")
        # Initialize
        $data = ""
        $data = "$formattedDate  ::::: $macAddress :::: $hostname ::: $ssid :: $dnsSuffix : $dnsServers"

        # Remote creds
        # Connect to the remote Windows 10 machine & log configured hosts
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.80.55" -Force
        $remoteComputer = "192.168.80.55"
        $username = "JohnDoe"
        $password = ConvertTo-SecureString "123" -AsPlainText -Force
        $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password

        # wh.lab (80.52)
        if ($dnsSuffix -eq 'jumwh.lab' -and $dnsServers -contains '192.168.80.52' -and $dnsServers -contains '8.8.8.8') 
        {
            Write-Output "DNS configuration is correct."
            # Register DNS and log
            Write-Output "-----------------"
            ipconfig /registerdns
            Write-Output "-----------------"
            Write-Output "DNS Has Been Registered!"
            $data += " :> DNS Registered"
            Write-Output "DNS Data: $data"

            #---------- log to remote host 
            try
            {
                $session = New-PSSession -ComputerName $remoteComputer -Credential $credentials
                if ($session.State -eq "Opened")
                {
                    Write-Host "Session established successfully."
                    # Continue with the code that depends on the successful session.
                    # Append the data to the file on the remote machine
                    Invoke-Command -Session $session -ScriptBlock{
                    Param($data)
                    Add-Content -Path "C:\conf\dnsRegs.txt" -Value $data.ToString()
                    } -ArgumentList $data

                    # Close the remote session
                    Remove-PSSession -Session $session
                }
                else
                {
                    Write-Host "Session failed to open there4 logging locally"
                    # If the remote host is not reachable, log to localhost and close the session..
                    #--------------- log this Locally
                    if (-not (Test-Path -Path "C:\conf\wifiLogs.txt")) 
                    {
                        New-Item -ItemType File -Path "C:\conf\wifiLogs.txt" -Force | Out-Null
                        Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$data"
                        Write-Output "Data logged locally!"
                    }
                    else 
                    {
                        <# Action when all if and elseif conditions are false #>
                        # add the datetime ...
                        Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$data"
                        Write-Output "Data logged locally!"
                    }
                    #--------------- END log this Locally
                }
            }
            catch
            {
                # if the error will be shown to the use, then it's better to comment it out
                Write-Host "An error occurred while establishing the session: $($_.Exception.Message)"
                # Handle the error appropriately.
                # If the remote host is not reachable, log to localhost and close the session..
                
                #--------------- log this Locally
                if (-not (Test-Path -Path "C:\conf\wifiLogs.txt")) 
                {
                    New-Item -ItemType File -Path "C:\conf\wifiLogs.txt" -Force | Out-Null
                    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$data"
                    Write-Output " We are @ catch block. Going to log locally!"
                }
                else 
                {
                    <# Action when all if and elseif conditions are false #>
                    # add the datetime ...
                    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$data"
                    Write-Output " We are @ catch block. Going to log locally!"
                }
                #--------------- END log this Locally
            }
            #--------------- END log to remote host 
        } 
        else 
        {
            Write-Output "DNS configuration is not as expected."
            # set the correct IPs and Register DNS and log
            $networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
            $dns = '192.168.80.52','8.8.8.8' # wh lab
            #$dns = '10.8.8.15','8.8.8.8' # UH
            $networkconfig.SetDNSServerSearchOrder($dns)
            #$DNSsuffix = 'uh.lab' #union house
            $DNSsuffix = 'jumwh.lab' #warehouse
            #$DNSsuffix = 'uh.lab'
            $networkConfig.SetDnsDomain($DNSsuffix)
            
            $class = [wmiclass]'Win32_NetworkAdapterConfiguration'
            $class.SetDNSSuffixSearchOrder($DNSsuffix)
            $networkConfig.SetDynamicDNSRegistration($true,$true)
            ipconfig /registerdns
            $data += " :> DNS Suffix Set & Registered"

            #--------------- Log this 
            try
            {
                $session = New-PSSession -ComputerName $remoteComputer -Credential $credentials
                if ($session.State -eq "Opened")
                {
                    Write-Host "Session established successfully."
                    # Continue with the code that depends on the successful session.
                    # Append the data to the file on the remote machine
                    Invoke-Command -Session $session -ScriptBlock{
                    Param($data)
                    Add-Content -Path "C:\conf\dnsRegs.txt" -Value $data.ToString()
                    } -ArgumentList $data

                    # Close the remote session
                    Remove-PSSession -Session $session
                }
                else
                {
                    Write-Host "Session failed to open."
                    # If the remote host is not reachable, log to localhost and close the session..
                    #--------------- log this Locally
                    if (-not (Test-Path -Path "C:\conf\wifiLogs.txt")) 
                    {
                        New-Item -ItemType File -Path "C:\conf\wifiLogs.txt" -Force | Out-Null
                        Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$data"
                    }
                    else 
                    {
                        <# Action when all if and elseif conditions are false #>
                        # add the datetime ...
                        Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$data"
                    }
                    #--------------- END log this Locally
                }
            }
            catch
            {
                Write-Host "An error occurred while establishing the session: $($_.Exception.Message)"
                # If the remote host is not reachable, log to localhost and close the session..

                #--------------- log this Locally
                if (-not (Test-Path -Path "C:\conf\wifiLogs.txt")) 
                {
                    New-Item -ItemType File -Path "C:\conf\wifiLogs.txt" -Force | Out-Null
                    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$data"
                    Write-Output "logged locally.."
                }
                else 
                {
                    <# Action when all if and elseif conditions are false #>
                    # add the datetime ...
                    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$data"
                    Write-Output "logged locally.."
                }
                #--------------- END log this Locally
            } # END catch

            #--------------- END log this 
        }
    } # if ($ssid -like "JUMIA-UH" -or $ssid -like "JUMIA-UH2")
    else 
    {
        <# Action when all if and elseif conditions are false #>
        # DO NOTHING. USER IS CONNECTED TO A WIFI BUT NOT JUMIA ...
        Write-Output "USER IS CONNECTED TO A WIFI THAT IS NOT PART OF JUMIA. NOTHING DOING .."
    }
    # ---- END Checking if on Jumia Wi-Fi, if not, do nothing
} 
else 
{
    Write-Output "Not connected to any Wifi Network."
    # Do Nothing ..
}

