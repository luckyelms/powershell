# globals
$script:LocalLogPath = "D:\dentonsAssets.csv"
$script:RemotePath = "C:\conf\dentonsAssets.csv"
$script:LogServer = "" # lab server
set-executionpolicy -ExecutionPolicy Unrestricted -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value $logServer -Force
# Import the credentials from the file.
# import only works if the same account used to create the creds in the begining!
if (-not (Test-Path -Path "C:\conf\credentials.xml" -PathType Leaf)) 
{
    $username = "JaneDoe"
    $password = ConvertTo-SecureString "123" -AsPlainText -Force
    $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password
}
else 
{
    $credentials = Import-Clixml -Path "C:\conf\credentials.xml"
}



############################################ START LOG ANSIBLE READY ###############################################
# $remoteComputer = "10.173.97.62"
$remoteComputer = "10.173.97.62"
$filePath = ""
$filePath = "C:\conf\ans.txt"
$data = ""
$data = $baseData
$data += " :> AnsibleReady!!"

Write-DataToFile -RemoteComputer $remoteComputer -Credentials $credentials -FilePath $filePath -Data $data

############################################ END SLOG ANSIBLE READY ###############################################

####### Log this locally & remotely:

# create the local log file:
if (-not (Test-Path -Path "C:\conf\wifiLogs.txt")) 
{
    New-Item -ItemType File -Path "C:\conf\wifiLogs.txt" -Force | Out-Null
    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$data"
}
else {
    <# Action when all if and elseif conditions are false #>
    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$data"
}
#############################################

###################  create secure creds:
# Prompt for password (since you can't transfer the original encrypted password)
$username = "JaneDoe"
$securePassword = Read-Host "Enter the Remote Log User Password" -AsSecureString
# Create new PSCredential object
$credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePassword
# Export the credentials to a new file
$credentials | Export-Clixml -Path "D:\credentials.xml"
# $remoteComputer = "192.168.100.9"

$filePath = ""
$filePath = "C:\conf\ansi.txt"

# Import the credentials from the file
$credentials = Import-Clixml -Path "C:\conf\credentials.xml"
$credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePassword

# call remote function:
Write-DataToFile -RemoteComputer $remoteComputer -Credentials $credentials -FilePath $filePath -Data $data
# delete the creds file

Write-Output "----------------------- Ansible Configurations done"

#############


