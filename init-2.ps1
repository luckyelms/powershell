# Set-ExecutionPolicy -ExecutionPolicy Unrestricted
# this comment tests git sync features...
<#
    Date: 12-11-23 @1238
    Ver 2:
        - adds cloud flare installation.
    Purpose: Required Laptop Initialization, app intallations etc

    Other Tasks:
        - set system restore on if not already set.
        - Change the timezone
        - Disable an account
        - Delete a user Account
        - Put the necessary icons on the taskbar
#>
# Loop until the user enters a valid drive letter or 'x' to exit
# $driveLetter must be global
    $script:driveLetter

##### START COUNT DOWN FUNCTION
function Start-CountDown {
    param (
        [string]$message,
        [int]$start,
        [int]$end  # Adjust the maximum count as needed
    )

    for ($count = $start; $count -ge $end; $count--) 
    {
        Write-Host "$message...$count"
        Start-Sleep -Seconds 1
    }
}

#### END: COUNTDOWN Function\
## Get the drive letter
do {
    $driveLetter = Read-Host "Enter the flash drive letter or 'x' to exit:"
    if ($driveLetter -eq 'x') 
    {
        Write-Host ".................. Exiting.. "
        
        break
    }
    $driveLetter += ":"
    $driveExists = Test-Path -Path $driveLetter -PathType Container
    if (-not $driveExists) 
    {
        Write-Host "Drive '$($driveLetter):\' not found. Please try again."
    }
} until ($driveExists)

# If the user chose to exit, stop
if ($driveLetter -eq 'x') 
{
    exit
}

# Display the menu
Write-Host "|||||||||||||||||||| MENU ||||||||||||||||||||||||||||||||||"
Write-Host "1. Create Windows User Account"
Write-Host "2. IT Admin Account"
Write-Host "3. Install XCALLY"
Write-Host "4. Set Host Name"
Write-Host "5. Instsall cloud Flare"
Write-Host "6. Standardise A User Account"
Write-Host "x. Exit"

# Parse the user's input for selected tasks
$selectedTasks = Read-Host "Enter the numbers of the tasks you want to perform (e.g., '1 2 3'):"
$selectedTasks = $selectedTasks -split '\s+' | ForEach-Object { [int]$_ }

# Define functions for the tasks
function CreateUserAccount 
{
    $UserNames = Read-Host "Enter the names of the Laptop user (e.g., John Wick):"
    $userName = $UserNames -replace ' ', '.' # Replace spaces with dots
    
    Write-Host "-------------- Creating Laptop User account.........."
    $sPassword = ConvertTo-SecureString "123" -AsPlainText -Force

    # Create the user account
        New-LocalUser -Name "$Username" -Password $sPassword -FullName $UserNames -Description $UserNames -PasswordNeverExpires
    Add-LocalGroupMember -Group "Users" -Member "$Username"
    Write-Host "`r`n`r`n"  # Move the cursor down two lines
    Write-Host "||||||||||||||||||| User account '$userName' created."
}

function CreateITAdminAccount 
{
    Write-Host "`r`n`r`n"  # Move the cursor down two lines
    Write-Host "-------------- Creating Admin Account.........."
    $AdminName = "itadmin" # change to itadmin when done testing ...
    $AdminGroup = "Administrators"
    $RmuGroup = "Remote Management Users"
    # Read the encrypted string from the file
    # $driveLetter
    $encryptedString = Get-Content -Path "$driveLetter\adm.txt"

    # Decrypt the string using Base64 decoding
        $decryptedBytes = [Convert]::FromBase64String($encryptedString)
        $decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    # Output the decrypted string
        Write-Host "Decrypted String: $decryptedString"
    # Convert the plain string password to a SecureString
        $securePassword = ConvertTo-SecureString $decryptedString -AsPlainText -Force
    # Check if the user exists
        $UserExists = Get-LocalUser -Name $AdminName -ErrorAction SilentlyContinue
    if (-not $UserExists) 
    {
        # Create the user account
            New-LocalUser -Name "$AdminName" -Password $securePassword -FullName "IT Admin" -Description "IT Admin Account" -AccountNeverExpires -PasswordNeverExpires
        # Add the user to the "Remote Management Users" group
            Add-LocalGroupMember -Group $AdminGroup -Member "$AdminName"
            Add-LocalGroupMember -Group $RmuGroup -Member "$AdminName"
        Write-Output "||||||||||||||||||| $AdminName ACCOUNT DID NOT EXIST... Created!!"
        Write-Host "`r`n`r`n"  # Move the cursor down two lines
    } 
    elseif($UserExists) 
    {
        Write-Output "The admin account Already exists"
        # Check if the user is a member of the group using net localgroup
            $IsMember = net localgroup "$RmuGroup" | Select-String -Pattern $AdminName
        if (-not $IsMember) 
        {
            # User is not a member, add the user to the group
            Add-LocalGroupMember -Group $RmuGroup -Member $AdminName
             Write-Output "Added to $RmuGroup"
        }
        else
        {
            Write-Output "$AdminName is already a member of remote dekstop Management users"
        }
    }
    
    Write-Host "IT Admin account created and configured."
}

# ---- hostname function
function SetHotName
{
    # Define the expected hostname pattern
    $expectedPattern = 'UG-[A-Z0-9]{3,15}-\d{3}-[A-Za-z]+$'
# Prompt the user for the hostname
    $hostname = hostname
    $sn = Get-WmiObject Win32_Bios | Select-Object -ExpandProperty SerialNumber
# Check if the entered hostname matches the expected pattern
    if ($hostname -match $expectedPattern) 
    {
        Write-Host "|||||||||||||||||| Hostname Pattern is valid."

        # Extract the 3-digit number and names
            $san = $hostname -split '-'
            $serialNumber = $san[1]
            $assetTag = $san[2]
            $names = $san[3]
        # Check if the 3-digit number matches the user's laptop
        $userInput = Read-Host "Please confirm that the last 3-digits on the Asset Tag are $assetTag & Your Names are: $names !? (y/n)"
        if ($userInput -eq "y") 
        {
            Write-Host "Serial Number: $serialNumber"
            Write-Host "Name: $names"
            Write-Host "Host Name: $hostname"

            if ($sn -ne $serialNumber)
            {
                $serialNumber = $sn
                $hostname = "UG-$serialNumber-$newAssetTag-$newName"
                rename-computer $hostname -F
                Write-Host "The Serial Number Did Not Match... Hostname has been aupdated...Restarting"
                Restart-Computer -F
            }
        } 
        elseif ($userInput -eq "n") 
        {
            # Prompt the user to enter the correct 3-digit number and name
                $newAssetTag = Read-Host "Enter the last 3-digits on the Asset Tag: "
                $newName = Read-Host "Enter your names Of The Laptop Owner e.g JohnWick: "
            # Update the hostname
                $hostname = "UG-$serialNumber-$newAssetTag-$newName"
                Write-Host "Updated Hostname: $hostname"
            # Change hostname
                rename-computer $hostname -F
            # Restart the host
                Restart-Computer -F
        }
    } 
    else  # hostname is invalid
    {
        Write-Host "||||||||||  HOSTNAME IS NOT VALID.... let's Change it"
        $newAssetTag = Read-Host "||||||||||  ENTER THE LAST 3 DIGITS ON THE ASSET TAG ATTACHED TO YOUR LAPTOP: "
        $newName = Read-Host "||||||||||  Enter your names Like this JohnWick:"
        $hostname = "UG-$sn-$newAssetTag-$newName"
        rename-computer $hostname -F
        Restart-Computer -F
    }
}
# ---- hostname function

function InstallXCALLY 
{
    $msiPath = "$($driveLetter):\xcally.msi"
    if (Test-Path -Path $msiPath) 
    {
        # Install XCALLY using your preferred method (e.g., Start-Process)
        # Example: Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $msiPath /qn"
        Write-Host "XCALLY installed."
    } 
    else 
    {
        Write-Host "XCALLY installation file not found."
    }
}

function InstallCloudFlare 
{
    # 2do: first check if the executable file is present..

    $msiPath = "$($driveLetter):\Cloudflare_WARP_Release-x64.msi"
    if (Test-Path -Path $msiPath) 
    {
        # Install 
        # Start the installation process and wait for it to complete
        Write-Host "Installing CloudFlare.. Please wait...."
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $msiPath /quiet" -PassThru -Wait
        # Check the exit code of the installation process
        if ($exitCode -eq 0 -or $exitCode -eq 3010) 
        {
            # Write-Host "Installation completed successfully."
            Start-CountDown -message "CloudFlare Installation completed successfully" -start 5 -end 1
        } 
        else 
        {
            # Write-Host "Installation failed. Exit code: $($process.ExitCode)"
            Start-CountDown -message "CloudFlare Installation failed. Exit code: $($process.ExitCode)" -start 5 -end 1
        }

    }
    else 
    {
        Start-CountDown -message "The cloudFlare executatble does not exist on the specified drive.. proceeding in " -start 5 -end 1
    }
}

function Deploy-ManageEngine 
{
    # 2do: first check if the executable file is present..

    $msiPath = "$($driveLetter):\ManageEngineUG.exe"
    if (Test-Path -Path $msiPath) 
    {
        # Install 
        # Start the installation process and wait for it to complete
        Write-Host "Installing Manage Engine.. Please wait...."
        $process = Start-Process -FilePath "ManageEngineUG.exe" -ArgumentList "/i $msiPath /quiet" -PassThru -Wait
        # Check the exit code of the installation process
        if ($exitCode -eq 0 -or $exitCode -eq 3010) 
        {
            # Write-Host "Installation completed successfully."
            Start-CountDown -message "Manage Engine UG Installation completed successfully" -start 5 -end 1
        } 
        else 
        {
            # Write-Host "Installation failed. Exit code: $($process.ExitCode)"
            Start-CountDown -message "ManageEngine UG Installation failed. Exit code: $($process.ExitCode)" -start 5 -end 1
        }

    }
    else 
    {
        Start-CountDown -message "The cloudManageEngine UG executatble does not exist on the specified drive.. proceeding in " -start 5 -end 1
    }
}

# Standardize user account:
function RenameUserAccount
{
    <#
    Date: 20-06-24 @1638
    Ver 1:
      Purpose: Rename current user account to reflect the name of the assigned laptop user.
      Not yet tested..
    #>
    # Function to list all users and select one
    function Select-User {
        $users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select-Object -ExpandProperty Name
        for ($i = 0; $i -lt $users.Count; $i++) {
            Write-Host "$($i + 1). $($users[$i])"
        }
        $selection = Read-Host "Select a user by number"
        return $users[$selection - 1]
    }

    # Get logged in user
    $LoggedInuser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName).Split('\')[1]
    # Select a user
    $selectedUser = Select-User

    if ($selectedUser -eq $LoggedInuser)
    {
        Write-Host "The selected user ($selectedUser) is the same as the logged in user. This user account Meets the Standards required!"
    } 
    else 
    {
        do 
        {
            $newUsername = Read-Host "Enter a new username in the format firstname.secondname same as the users email (e.g., jane.doe): "
            $newUsernameValid = $newUsername -match '^[a-z]+\.[a-z]+$'
            if (-not $newUsernameValid) 
            {
                Write-Host "Invalid username. Please enter a valid username in the format firstname.secondname (e.g., jane.doe)."
            }
        } while (-not $newUsernameValid)

        # Split the username into firstname and secondname
        $parts = $newUsername -split '\.'
        # Capitalize the first letter of each part
        $firstName = $parts[0].Substring(0,1).ToUpper() + $parts[0].Substring(1).ToLower()
        $secondName = $parts[1].Substring(0,1).ToUpper() + $parts[1].Substring(1).ToLower()
        # Format the full name
        $fullName = "$firstName $secondName"
        Write-Host "The full name will be: $fullName"
        # Rename the user account
        Rename-LocalUser -Name $selectedUser -NewName $newUsername
        # Update the full name
        Set-LocalUser -Name $newUsername -FullName $fullName

        Write-Host "User $selectedUser has been renamed to $newUsername and the full name updated to $fullName."
    }
}


# Execute selected tasks
foreach ($task in $selectedTasks) 
{
    switch ($task) 
    {
        1 { CreateUserAccount }
        2 { CreateITAdminAccount }
        3 { InstallXCALLY }
        4 { SetHotName }
        5 { InstallCloudFlare }
        6 { RenameUserAccount}
        
        default { Write-Host "Invalid task number: $task" }
    }
}
Write-Host "`r`n`r`n"  # Move the cursor down two lines
Write-Host "All tasks completed."
