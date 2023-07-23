<#
    from windows to linux ..
#>

# Install the SSH module if not already installed
if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    Install-Module -Name Posh-SSH -Force
}

# Import the SSH module
Import-Module Posh-SSH

# Define the server details
$serverAddress = "192.168.100.10"
$serverUsername = "elmsx"
$serverPassword = "rmJam@"

# Create a session and login to the server
$session = New-SSHSession -ComputerName $serverAddress -Credential (Get-Credential -UserName $serverUsername -Password $serverPassword)

# Check if the session was created successfully
if ($session) {
    try {
        # Create the logs.txt file and append data
        Invoke-SSHCommand -SessionId $session.SessionId -Command "echo 'This is a sample test' >> logs.txt"

        Write-Host "Data appended to logs.txt successfully."
    } finally {
        # Close the session
        Remove-SSHSession -SessionId $session.SessionId
    }
} else {
    Write-Host "Failed to create the SSH session."
}
