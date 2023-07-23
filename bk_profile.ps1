# Step 1: Create a variable called wifi
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
    
    $addProfileCommand = "netsh wlan add profile filename=""C:\ProgramData\conf\$wifi.xml"""
    $addProfileResult = Invoke-Expression -Command $addProfileCommand

    if ($addProfileResult -eq $null)
    {
        # Command executed successfully, create scheduled task
        Write-Host "Command executed successfully."
        
        $deleteProfileCommand = "netsh wlan delete profile name=""JUMIA-UH2"""
        # Create a scheduled task to run the delete profile command
        # ...
    } 
    else
    {
        Write-Host "Error executing command."
    }
} 
else
{
    # File does not exist, write to a text file
    Write-Host "File $wifi.xml not found."
    
    $notFoundMessage = """$wifi.xml"" not found."
    $notFoundFilePath = "C:\ProgramData\conf\file_not_found.txt"
    Out-File -FilePath $notFoundFilePath -InputObject $notFoundMessage
}
