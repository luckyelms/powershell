<#
    Simple script to test connection to a windows remote host and log DNS registration requests
    This snippet will be part of the registerdns1.0.ps1 & awx-1.2.ps1 code.
    - the remote user must be part of the remote management user's group                                                                                                                                                         
    
    Logs:
        - 17.07.23 @1120: Worked perfectly.

#>

# Connect to the remote Windows 10 machine & log configured hosts
#Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.80.55" -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.100.9" -Force
$remoteComputer = "192.168.100.9"
$username = "JaneDoe" 
$password = ConvertTo-SecureString "123" -AsPlainText -Force 
$credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password

# code below will be replace "$session = New-PSSession -ComputerName $remoteComputer -Credential $credentials"

$data = "Testing remote logging ..."
Write-Host "Bombo: Going to Open Session."

try
{
    $session = New-PSSession -ComputerName $remoteComputer -Credential $credentials
    if ($session.State -eq "Opened")
    {
    Write-Host "Session established successfully."
    # Continue with the code that depends on the successful session.
    # Append the data to the file on the remote machine
    Invoke-Command -Session $session -ScriptBlock{
    Param($data)
    Add-Content -Path "C:\conf\dnsRegs.txt" -Value $data.ToString()
    } -ArgumentList $data

    # Close the remote session
    Remove-PSSession -Session $session
    }
    else
    {
        Write-Host "Bombo: Session failed to open."
         # If the remote host is not reachable, log to localhost and close the session..
    }
}
catch
{
    Write-Host "An error occurred while establishing the session: $($_.Exception.Message)"
    # Handle the error appropriately.
    # If the remote host is not reachable, log to localhost and close the session..

}
