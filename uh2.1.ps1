<#
    Date: 26-06-23 @1645
    1. Function: 
        - connect to Jumia-uh2; 
        - Delete Jumia-uh
        - A corresponding script for JUMIA-UH2 will be created.
    2. Narration: This script is adapted from profile.ps1 and supercedes it.
    Ideas:
        - Logging 2b written on both local host and remote host.
    Log:
        - Worked perfectly!
        - 29-06-23 @0431: modified to write logs to a rlocal host (c:/conf).
        - 10-07-23 @1404: bind9 re-gistration after successful migration to JUMIA-UH2

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
        ipconfig /registerdns
        
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
}
