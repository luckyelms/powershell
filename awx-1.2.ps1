<#
    Ver: 1.2
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

# configure for ansible
Write-output "Configuring for Ansible..."
$url = "https://github.com/ansible/ansible/blob/temp-2.10-devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
$file = "$env:temp\ConfigureRemotingForAnsible.ps1"
(New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file)
powershell.exe -ExecutionPolicy ByPass -File $file
# END configure for ansible

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
$networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
$dns = '10.8.8.15','8.8.8.8' # home lab
#$dns = '10.8.8.15','8.8.8.8'
$networkconfig.SetDNSServerSearchOrder($dns)
#$DNSsuffix = 'uh.lab' #union house
#$DNSsuffix = 'jumwh.lab' #warehouse
$DNSsuffix = 'uh.lab'
$networkConfig.SetDnsDomain($DNSsuffix)

$class = [wmiclass]'Win32_NetworkAdapterConfiguration'
$class.SetDNSSuffixSearchOrder($DNSsuffix)
$networkConfig.SetDynamicDNSRegistration($true,$true)
ipconfig /registerdns


#------------ Record/Log the mac address and hostname to remote host:
# Get MAC address and hostname of the local Windows computer
# Get the mac address of the current active wi-fi interface...

Write-output "Logging ................................................"

# $macAddress = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }).MACAddress
#$macAddress = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "Wi-Fi*" } | Select-Object -ExpandProperty MacAddress

#home lab VM use ethernet not wi-fi
$macAddress = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "Wi-Fi*" } | Select-Object -ExpandProperty MacAddress

$hostname = hostname

# date
$dat = Get-Date
$formattedDate = $dat.ToString("dd-MM-yy HH:mm:ss")

# Create a text string with the MAC address and hostname
$data = ""

$data = "$formattedDate  ::: $macAddress :: $hostname"

# Connect to the remote Windows 10 machine & log configured hosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.8.8.20" -Force
$remoteComputer = "10.8.8.20"
$username = "JaneDoe"
$password = ConvertTo-SecureString "123" -AsPlainText -Force
$credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password
$session = New-PSSession -ComputerName $remoteComputer -Credential $credentials

<#
    -- code below will be replace "$session = New-PSSession -ComputerName $remoteComputer -Credential $credentials"

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
                Add-Content -Path "C:\conf\macs.txt" -Value $data.ToString()
            } -ArgumentList $data

            # Close the remote session
            Remove-PSSession -Session $session
        }
        else
        {
            Write-Host "Session failed to open."
            # Handle the failure appropriately.
        }
    }
    catch
    {
        Write-Host "An error occurred while establishing the session: $($_.Exception.Message)"
        # Handle the error appropriately.
    }

#>

# Append the data to the file on the remote machine
Invoke-Command -Session $session -ScriptBlock{
    Param($data)
    Add-Content -Path "C:\conf\macs.txt" -Value $data.ToString()
} -ArgumentList $data

# Close the remote session
Remove-PSSession -Session $session
