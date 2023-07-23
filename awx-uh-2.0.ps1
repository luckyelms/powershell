<#
    Ver: 2.0:
        - supercedes awx-1.2
        -
    Tasks:
        1. 
    
	$ErrorActionPreference = "continue"
	Status: Started 17-07-23 @1430 > in-progress...
            
	Logs:
     - 
    2DO:
        - 
#>

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

# setup DNS settings:
$wifiInterface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "Wi-Fi*" }

if ($wifiInterface) 
{
    # ---- Checking if on Jumia Wi-Fi, if not, do nothing
    $ssid = (netsh wlan show interfaces | Select-String 'SSID').Line.Split(':')[1].Trim()
    if ($ssid -like "JUMIA-UH" -or $ssid -like "JUMIA-UH2")
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
        <#
            Write-Output "Connected Wi-Fi network (SSID): $ssid"
            Write-Output "Network Adapter: $($adapterDetails.Name)"
            Write-Output "DNS Suffix: $dnsSuffix"
            Write-Output "DNS Servers: $dnsServers"
            Write-Output "Mac Address: $macAddress"
            Write-Output "Host Name: $hostName"
        #>
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
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.8.8.20" -Force
        $remoteComputer = "10.8.8.20"
        $username = "JaneDoe"
        $password = ConvertTo-SecureString "123" -AsPlainText -Force
        $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password

        # uh.lab (8.15)
        if ($dnsSuffix -eq 'uh.lab' -and $dnsServers -contains '10.8.8.15' -and $dnsServers -contains '8.8.8.8') 
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
            $dns = '10.8.8.15','8.8.8.8' # home lab
            #$dns = '10.8.8.15','8.8.8.8' # UH
            $networkconfig.SetDNSServerSearchOrder($dns)
            #$DNSsuffix = 'uh.lab' #union house
            #$DNSsuffix = 'jumwh.lab' #warehouse
            $DNSsuffix = 'uh.lab'
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
