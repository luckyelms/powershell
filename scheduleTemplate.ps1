<#
    - Purpose: Create a scheduled task using powershell.
    - will be run either via ansible or locally in order to create the schedule.

#>

# Define the task schedule start and end times (6 hours)
$startTime = (Get-Date).Date.AddHours(8)   # 8:00 AM
$endTime = (Get-Date).Date.AddHours(14)    # 2:00 PM

# Define the task action (replace with your desired script/command)
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "c:\ProgramData\conf\registerdns-wh-1.0.ps1"

# Define the trigger for the task (runs every minute)
$taskTrigger = New-ScheduledTaskTrigger -Daily -At $startTime -DaysInterval 1 -RandomDelay (New-TimeSpan -Minutes 1)

# Set the duration to 6 hours
$taskDuration = New-TimeSpan -Hours 6

# Create a new task using the provided parameters
Register-ScheduledTask -TaskName "YourTaskName" -Action $taskAction -Trigger $taskTrigger -User "YourUsername" -Password "YourPassword" -RunLevel Highest -Settings (New-ScheduledTaskSettingsSet -DontStopIfGoingOnBatteries:$false -AllowStartIfOnBatteries:$true) -StartTime $startTime -EndTime $endTime -Duration $taskDuration
