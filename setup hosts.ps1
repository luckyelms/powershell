<#
    1. configure ssh
    2. setup DNS
    This file supercedes previous settings using winrm feature.
	$ErrorActionPreference = "continue"
	set-executionpolicy -ExecutionPolicy RemoteSigned
	# VkQL5fu#T
#>
# allow ICMP
netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow

# Install OenSSH
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

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
#$dns = '192.168.100.250','8.8.8.8' # home lab
$dns = '10.8.8.15','8.8.8.8'
$networkconfig.SetDNSServerSearchOrder($dns)
$DNSsuffix = 'uh.lab' #union house
# $DNSsuffix = 'jumwh.lab' #warehouse
#$DNSsuffix = 'uh.lab'
$networkConfig.SetDnsDomain($DNSsuffix)

$class = [wmiclass]'Win32_NetworkAdapterConfiguration'
$class.SetDNSSuffixSearchOrder($DNSsuffix)
$networkConfig.SetDynamicDNSRegistration($true,$true)
ipconfig /registerdns

# configure for ansible
Write-output "Configuring for Ansible..."
$url = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
$file = "$env:temp\ConfigureRemotingForAnsible.ps1"
(New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file)
powershell.exe -ExecutionPolicy ByPass -File $file

#-------------------- Record the mac address and hostname to remote host:
# Get MAC address and hostname of the local Windows computer
# the mac address could better be pulled using the get-networkAdapter
$macAddress = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }).MACAddress
$hostname = (Get-WmiObject -Class Win32_ComputerSystem).Name

# Create a text string with the MAC address and hostname
$data = "$macAddress,$hostname"

# Connect to the remote Windows 10 machine
$remoteComputer = "192.168.100.104"
$username = "tom"
$password = ConvertTo-SecureString "123" -AsPlainText -Force
$credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password
$session = New-PSSession -ComputerName $remoteComputer -Credential $credentials

# Append the data to the file on the remote machine
Invoke-Command -Session $session -ScriptBlock {
    Param($data)
    Add-Content -Path "C:\conf\macs6.txt" -Value $data.ToString()
} -ArgumentList $data

# Close the remote session
Remove-PSSession -Session $session
