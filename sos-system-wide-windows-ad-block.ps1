# Set error action preference to silently continue
$ErrorActionPreference = 'SilentlyContinue'

# Elevate privileges for the script
Write-Output "Elevating privileges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

# Set the current directory to the script's root directory
$scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Set-Location -Path $scriptRoot

# Output information about the ad blocker project
Write-Host "Implementing simeononsecurity/System-Wide-Windows-Ad-Blocker" -ForegroundColor Green -BackgroundColor Black
Write-Host "https://github.com/simeononsecurity/System-Wide-Windows-Ad-Blocker" -ForegroundColor Green -BackgroundColor Black

# Specify the hosts file location
$hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"

# Use only the latest .NET version
$regPath1 = "HKLM:\SOFTWARE\Microsoft\.NETFramework"
$regPath2 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
New-ItemProperty -Path $regPath1 -Name "OnlyUseLatestCLR" -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path $regPath2 -Name "OnlyUseLatestCLR" -PropertyType DWORD -Value 1 -Force

# Download the StevenBlack/hosts file
$repoUrl1 = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
$repoUrl2 = 'http://sbc.io/hosts/hosts'

# Test if web access to the repo is available, if so download the latest version of the hosts file
$webRequest1 = [System.Net.WebRequest]::Create($repoUrl1)
$webResponse1 = $webRequest1.GetResponse()
$httpStatus1 = [int]$webResponse1.StatusCode

$webRequest2 = [System.Net.WebRequest]::Create($repoUrl2)
$webResponse2 = $webRequest2.GetResponse()
$httpStatus2 = [int]$webResponse2.StatusCode

if ($httpStatus1 -eq 200) {
    Write-Host "Repo Access is Available. Downloading Latest Host File" -ForegroundColor White -BackgroundColor Black
    Invoke-WebRequest -Uri $repoUrl1 -OutFile "$scriptRoot\Files\hosts.txt"
    Write-Host "Writing to System Host File...." -ForegroundColor White -BackgroundColor Black

    try {
        Set-Content -Path $hostsFilePath -Value "" -Encoding ASCII
        Get-Content -Path "$scriptRoot\Files\hosts.txt" | Add-Content -Path $hostsFilePath -Encoding ASCII
        Write-Host "Write Successful.." -ForegroundColor Green -BackgroundColor Black
    }
    catch {
        Write-Host "Error writing to System Host File...." -ForegroundColor Red -BackgroundColor Black
    }
}
elseif ($httpStatus2 -eq 200) {
    Write-Host "Repo Access is Available. Downloading Latest Host File" -ForegroundColor White -BackgroundColor Black
    Invoke-WebRequest -Uri $repoUrl2 -OutFile "$scriptRoot\Files\hosts.txt"
    Write-Host "Writing to System Host File...." -ForegroundColor White -BackgroundColor Black

    try {
        Set-Content -Path $hostsFilePath -Value "" -Encoding ASCII
        Get-Content -Path "$scriptRoot\Files\hosts.txt" | Add-Content -Path $hostsFilePath -Encoding ASCII
        Write-Host "Write Successful.." -ForegroundColor Green -BackgroundColor Black
    }
    catch {
        Write-Host "Error writing to System Host File...." -ForegroundColor Red -BackgroundColor Black
    }
}
