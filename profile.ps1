# pre-

if (-not (Test-Path -Path "C:\conf\wifiLogs.txt")) 
{
    New-Item -ItemType File -Path "C:\conf\wifiLogs.txt" -Force | Out-Null
    $log = Get-Date
    $log = $log.ToString()
    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$log Starting..."

}
else 
{
    <# Action when all if and elseif conditions are false #>
    # add the datetime ...
    $log = Get-Date
    $log = $log.ToString()
    Add-Content -Path "C:\conf\WifiLogs.txt" -Value "$log Starting..."
}


# Step 1: Create a variable  called wifi
$wifi = ""

# Step 2: Get the current date and extract the current month and year
$currentDate = Get-Date
$currentMonthYear = $currentDate.ToString("MM-yyyy")

# Step 3: Append and prefix 29 to the current month and year
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
        }

        # then delete the profile
        # Remove-Item -Path $wifi.xml
        
        
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
