

$wifiInterface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "Wi-Fi*" }
if ($wifiInterface) 
{
    $ssid = (netsh wlan show interfaces | Select-String 'SSID').Line.Split(':')[1].Trim()
    $adapterDetails = Get-NetAdapter -Name $wifiInterface.Name
    $dnsSuffix = (Get-DnsClientGlobalSetting).SuffixSearchList
    
    # Get the DNS IPs
    $dnsServers = $adapterDetails | Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses

    # Get the mac address:
    $macAddress = $wifiInterface.MacAddress
    # host Name
    $hostName = hostname
    
    # Testing ...
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

        #---------- log this 
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
            }
        }
        catch
        {
            Write-Host "An error occurred while establishing the session: $($_.Exception.Message)"
            # Handle the error appropriately.
            # If the remote host is not reachable, log to localhost and close the session..
        }
        #--------------- END log this 
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
        $data += "> DNS Suffix Set & Registered"
    }
} 
else 
{
    Write-Output "Not connected to a JUMIA/Home network."
    # Do Nothing ..
}
