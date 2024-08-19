<# 
    1. rename all files in a directory even file names with special characters e.g []
#>

# Define the directory path
$directoryPath = "E:\GeneralDownloads\RHCSA"

# Define the string to remove
$removeString = "--- [ FreeCourseWeb.com ] ---"

# Get all files in the directory
$files = Get-ChildItem -Path $directoryPath -File

foreach ($file in $files) 
{
    # Define the old file name and the new file name
    $oldFileName = $file.FullName
    $newFileName = $file.Name -replace [regex]::Escape($removeString), ''

    # Define the new file path
    $newFilePath = Join-Path -Path $directoryPath -ChildPath $newFileName

    # Print the file processing details
    Write-Host "Processing file: $oldFileName"
    Write-Host "New file name: $newFilePath"

    # Rename the file if the new file path is different from the old file path
    if ($oldFileName -ne $newFilePath) {
        try {
            Rename-Item -LiteralPath $oldFileName -NewName $newFileName -Force
            Write-Host "Successfully renamed to: $newFilePath"
        } catch {
            Write-Host "Error renaming file: $_"
        }
    } else {
        Write-Host "No change needed for file: $oldFileName"
    }
}
