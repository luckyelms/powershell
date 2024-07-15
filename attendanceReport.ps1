<#
    Automate Dentons Weekly attendance report.
    1. save csv file as excel file


#>
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
$inputCSV = "C:\Users\bombo.mustapha\OneDrive - Dentons\Documents\Attendance Reports\Attendance Details_01.07.24_07.07.24.csv"
$outputXLSX = "C:\Users\bombo.mustapha\OneDrive - Dentons\Documents\Attendance Reports\Attendance_01.07.24_07.07.24.xlsx"

Install-Module importexcel
Import-CSV -Path "C:\Users\bombo.mustapha\OneDrive - Dentons\Documents\Attendance Reports\Attendance Details_01.07.24_07.07.24.csv" | Export-Excel -Path "C:\Users\bombo.mustapha\OneDrive - Dentons\Documents\Attendance Reports\Attendance_01.07.24_07.07.24.xlsx"
