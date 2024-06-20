<#
    Date: 20-06-24 @1638
    Ver 1:
      Purpose: Rename current user account to reflect the name of the assigned laptop user
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
        $newUsername = Read-Host "Enter a new username in the format firstname.secondname (e.g., jane.doe): "
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
