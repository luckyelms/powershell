<#
    Date: 26-06-23 @1645
    1. Function: Delete Jumia-uh & connect to Jumia-uh2; A corresponding script for JUMIA-WH will be created.
    2. Ver: 2.2, supercedes & will replace 2.1
    
    Ideas:
        - Logging 2b written on both local host and remote host. > In progress..
        - Re-gristration of IP settings with bind9
    Log:
        - In progress..
        - 

#>

if (-not (Test-Path -Path "C:\conf\wifiLogs.txt")) 
{
    New-Item -ItemType File -Path "C:\conf\wifiLogs.txt" -Force | Out-Null
    $log = Get-Date
    $log = $log.ToString()
    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$log Starting..."

}
else 
{
    # add the datetime ...
    $log = Get-Date
    $log = $log.ToString()
    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$log Starting..."

    #get the hostname & mac address..append
}

# Step 1: Create a variable  called wifi
$wifi = ""

# Step 2: Get the current date and extract the current month and year
$currentDate = Get-Date
$currentMonthYear = $currentDate.ToString("MM-yyyy")

# Step 3: Append and prefix 29 to the current month and year
# 29 is the date password or wifi switch will take place
$wifi = "29-$currentMonthYear"

# Step 4: Check if the file with the name equal to the wifi variable exists
$filePath = "C:\ProgramData\conf\$wifi.xml"

# hostname is global
$hostname = hostname

# session is global too
# Connect to the remote Windows 10 machine & log configured hosts
# Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.8.8.20" -Force
# Home lab
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.100.9" -Force

#$remoteComputer = "10.8.8.20"
# Home Lab log host
$remoteComputer = "192.168.100.9"

$username = "JaneDoe"
$password = ConvertTo-SecureString "123" -AsPlainText -Force
$credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password


if (Test-Path -Path $filePath)
{
    # File exists, execute the command
    Write-Host "File $wifi.xml found."
    # create log file. no need to recreate within the main if () block
    $log = Get-Date
    $log = $log.ToString()
    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$log wiFi profile file found..."

    $addProfileCommand = "netsh wlan add profile filename=""C:\ProgramData\conf\$wifi.xml"""
    $addProfileResult = Invoke-Expression -Command $addProfileCommand

    # 
    if ($addProfileResult -like "*is added on interface*")
    {
        # Command executed successfully, 
        # write to log file ..
        Write-Host "Command executed successfully."
        $log = Get-Date
        $log = $log.ToString()
        Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$log wiFi profile succesfully added. Message: '$addProfileResult'"

        # Re-gister IP settings with bind9
        $networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
        $dns = '10.8.8.15','8.8.8.8'
        $networkconfig.SetDNSServerSearchOrder($dns)
        $DNSsuffix = 'uh.lab' #union house
        $networkConfig.SetDnsDomain($DNSsuffix)
        $class = [wmiclass]'Win32_NetworkAdapterConfiguration'
        $class.SetDNSSuffixSearchOrder($DNSsuffix)
        $networkConfig.SetDynamicDNSRegistration($true,$true)
        $registerDnsResult = ipconfig /registerdns
        if ($registerDnsResult -like "*all adapters of this computer has been initiated*")
        {
            # log it..
            Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$log ::: IP-hostname registered bind9"

        }
        else 
        {
            Add-Content -Path "C:\conf\WifiLogs.txt" -Value "Registration with bind9 failed. Error: '$registerDnsResult'"
        }
        # END Re-gister IP settings with bind9

        #---------------- write to remote log
        try
        {
            $session = New-PSSession -ComputerName $remoteComputer -Credential $credentials
            if ($session.State -eq "Opened")
            {
                Write-Host "Session established successfully."
                # Continue with the code that depends on the successful session.
                # Append the data to the file on the remote machine
                # date
                $dat = Get-Date
                $formattedDate = $dat.ToString("dd-MM-yy HH:mm:ss")
                # Create a text string with the MAC address and hostname
                $data = ""
                $data = "$formattedDate ::: $hostname :: $addProfileResult :"

                Invoke-Command -Session $session -ScriptBlock{
                    Param($data)
                    Add-Content -Path "C:\conf\WifiChangeLog.txt" -Value $data.ToString()
                } -ArgumentList $data
    
                # Close the remote session
                # Remove-PSSession -Session $session

                # log this too to local host
                Add-Content -Path "C:\conf\WifiLogs.txt" -Value "Remote Logged! Data: '$data'"
            }
            else
            {
                Add-Content -Path "C:\conf\WifiLogs.txt" -Value "Session to remote Log Server failed to open."
                # Handle the failure appropriately.
            }
        }
        catch
        {
            Write-Host "An error occurred while establishing the session: $($_.Exception.Message)"
            # Handle the error appropriately.
            Add-Content -Path "C:\conf\WifiLogs.txt" -Value "Session Failed. Message is: $($_.Exception.Message) ."
        }
        # END ---------------- write to remote log

        # Forget the previous wifi
        # $deleteProfileCommand = "netsh wlan delete profile name=""JUMIA-UH2"""
        $dropWifiProfileCommand = "netsh wlan delete profile name=""JUMIA-UH"""
        $dropWifiProfileResult = Invoke-Expression -Command $dropWifiProfileCommand

        # verify that previous profile has been removed..
        if ($dropWifiProfileResult -like "*is deleted from interface*")
        {
            # log it
            $log = Get-Date
            $log = $log.ToString()
            Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$log Previous wiFi profile succesfully deleted. Message: '$dropWifiProfileResult'"

            # then delete the xml file ...
            # Remove-Item -Path $wifi.xml
            # to succesfully remove the ps1 sript, the scheduled task must be have run succesfully,
            # which implies a second script/trigger...
        }

        
    } 
    else
    {
        # if the file is not there, the addProfileResult willbe 'The System cannot find the file specified'
        Write-Host "Error adding profile.."
        $log = Get-Date
        $log = $log.ToString()
        Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$log Profile failed!. Message is: $addProfileResult"
    }

    # close the remote session
    Remove-PSSession -Session $session
} 
else
{
    # File does not exist, write to a text file
    Write-Host "File $wifi.xml not found."
    $log = Get-Date
    $log = $log.ToString()
    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$log Profile file does not exist. Message is: $addProfileResult .Contact itadmin Bombo"

    #$notFoundMessage = """$wifi.xml"" not found."
    #$notFoundFilePath = "C:\conf\wifiLogs.txt"
    #Out-File -FilePath $notFoundFilePath -InputObject $notFoundMessage
    # this is a control comment ..ignore it

    # close the remote session
    Remove-PSSession -Session $session
}
