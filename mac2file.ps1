<#
    - the endpoint user must be part of remote management users group
    - To append data, u must -ScriptBlock else will fail
    - test: will this be applied?
#>

# Get MAC address and hostname of the local Windows computer
$macAddress = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "Wi-Fi*" } | Select-Object -ExpandProperty MacAddress
# $macAddress = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }).MACAddress
$hostname = hostname

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
