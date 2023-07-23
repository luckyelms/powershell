<#
    Ver: 1.0:
        - Exclusive to WH   
        - Set DNS ip only if host connected to Jumia wifi, otherwise do nothing..
    Tasks:
        1. Check if host is connected to JUMIAH-WH(2)
        2. if yes: check if DNS & search domains are correct, if not set
        3. Then register IP with Bind
    
	$ErrorActionPreference = "continue"
	Status: Started 18-07-23 @1425 > in-progress...
            -----: Ready 4deployement
	Logs:
     -
    2DO:
        - create a yaml schedule and run it every 3 hrs
        - Add remote logging. remote logging prototype remotehost.ps1 & adapter1.ps1 > DONE!
        - Add local logging in case remote logging fails > DONE
        - registerdns1.0.ps1 will be deprecated
#>

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
                    Write-Host "-----------------------------------"
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
                    Write-Host "-----------------------------------"
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

            $DNSsuffix = ""
            $data = ""
            $dns = ""

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
            
            $data = "$formattedDate  ::::: $macAddress :::: $hostname ::: $ssid :: $dnsSuffix : $dns"
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
