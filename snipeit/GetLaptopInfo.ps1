#### 
<#
    Purpose: Script gathers data for asset management system and writes the data to remote file or on a falsh disk.
    Date: 19.05.24
    Ver: 1.0
    Author: Bombo

#>
# Get the username of the person logged into the machine
    $user = [Environment]::UserName
# Get the full name of the user

    $user = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName).Split('\')[1]
    $fullName = $user -replace '\.', ' '
$System = Get-WmiObject  -Query "SELECT * FROM Win32_SystemEnclosure" -Namespace "root\CIMV2"
$ComputerSystem = Get-WmiObject  -Class Win32_ComputerSystem
$BIOS = Get-WmiObject  -Class Win32_BIOS
$BIOSageInYears = (New-TimeSpan -Start ($BIOS.ConvertToDateTime($BIOS.releasedate).ToShortDateString()) -End $(Get-Date)).Days / 365
# $OSInstallDate = ($OperatingSystem.ConvertToDateTime($OperatingSystem.InstallDate).ToShortDateString())
    $Serial = $System.SerialNumber
    $Manufacturer = $ComputerSystem.Manufacturer
    $ItemName = $ComputerSystem.Model
    $ManufacturedDate = ($BIOS.ConvertToDateTime($BIOS.releasedate).ToShortDateString())
    $BIOSageInYears = [Math]::Round($BIOSageInYears)
    $OSInstallDate = $OSInstallDate
    $GenericModel = "$Manufacturer Laptop"
# Get HD SIZE & TYPE
    #$HDTYPE = Get-PhysicalDisk | Select-Object -E.xpandProperty MediaType
    $HDTYPE = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq 0 } | Select-Object -ExpandProperty MediaType
    #$HDSIZE = Get-PhysicalDisk | Select-Object -ExpandProperty Size
    $HDSIZE = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq 0 } | Select-Object -ExpandProperty size
    # BusType
    $BusType = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq 0 } | Select-Object -ExpandProperty BusType 
    
    $HDSIZE = [Math]::Round($HDSIZE/1000000000)
# Get the Processor:
    $Processor = Get-WmiObject Win32_Processor | Select-Object -ExpandProperty name
# Get the operating system
    $OS = (Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
# ----- Static Data ------
    $Warranty = 12
    $Category = "Laptops"
    $Company = "Dentons"
    $Status = "Assigned"
    $Location = "HQ"
    $PurchaseDate = "8/29/2022"
    $email = "$user@dentons.com"
    $remotePath = "\\UG5CD120S00RL\assets\assets.csv"
# ----- END Static Data ------

## Print Info
Write-Host "------------- DATA OUTPUT--------"
Write-Host "Full Name: $fullName"
Write-Host "Logged In Username: $user"
Write-Host "email: $email"
Write-Host "Item Name: $ItemName"
Write-Host "Company: $Company"
Write-Host "Category: $Category"
Write-Host "Generic Model: $GenericModel"
Write-Host "Manufacturer: $Manufacturer"
Write-Host "SerialNumber: $Serial"
Write-Host "Location: $Location"
Write-Host "PurchaseDate = $PurchaseDate"
Write-Host "Status: $Status"
Write-Host "Warranty: $Warranty"

#Write-Host "Warranty: $Warranty"
#Write-Host "Warranty: $Warranty"

Write-Host "OperatingSystem: $OS"
Write-Host "Model: $Model"
Write-Host "ManufacturedDate: $ManufacturedDate"
Write-Host "Age: $BIOSageInYears" 
Write-Host "OS Install Date: $OSInstallDate"
Write-Host "HD Type: $HDTYPE"
Write-Host "HD Size: $HDSIZE"
Write-Host "Processor: $Processor"
Write-Host "Operating System: $OS"

############################ append to file
# Prepare the data to be written to the CSV file
# the remote file aleady has the headings.
$data = "$fullName,$user,$email,$ItemName,$Company,$Category,$GenericModel,$Manufacturer,$Serial,$Location,$PurchaseDate,$Status,$Warranty,$OS,$HDTYPE,$HDSIZE,$Processor,$BusType"

# Append the data to the CSV file
# Add-Content -Path "C:\CodeSnippets\snipe-it scripts\Dentons Assets - Dentons Assets.csv" -Value $data
# Add-Content -Path "C:\CodeSnippets\snipe-it scripts\Dentons Assets - Dentons Assets.csv" -Value $data
Add-Content -Path "D:\DentonsAssets.csv" -Value $data

Write-host "Data Added is: $data"