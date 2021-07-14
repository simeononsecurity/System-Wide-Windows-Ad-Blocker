# System-Wide-Windows-Ad-Blocker
# https://github.com/simeononsecurity/System-Wide-Windows-Ad-Blocker
# https://simeononsecurity.ch

#  Description:
#This script blocks Telemetry, Ad, and Malware related domains via the hosts file

#Continue on error
$ErrorActionPreference = 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator

#Set Directory to PSScriptRoot
if ((Get-Location).Path -NE $PSScriptRoot) { Set-Location $PSScriptRoot }

Write-Host "Implementing simeononsecurity/System-Wide-Windows-Ad-Blocker" -ForegroundColor Green -BackgroundColor Black
Write-Host "https://github.com/simeononsecurity/System-Wide-Windows-Ad-Blocker" -ForegroundColor Green -BackgroundColor Black

#Specify host file location
$hosts_file = "$env:systemroot\System32\drivers\etc\hosts"

#Use only latest .Net 
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType "DWORD" -Value "1" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType "DWORD" -Value "1" -Force

# Download the StevenBlack/hosts file
# Test if web access to the repo is available, if so download latest version of config
# First we create the request.
$HTTP_Request = [System.Net.WebRequest]::Create('https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts')
# We then get a response from the site.
$HTTP_Response = $HTTP_Request.GetResponse()
# We then get the HTTP code as an integer.
$HTTP_Status = [int]$HTTP_Response.StatusCode
If ($HTTP_Status -eq 200) {
    Write-Host "Repo Access is Available. Downloading Latest Host File" -ForegroundColor White -BackgroundColor Black
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" -OutFile $PSScriptRoot/Files/hosts.txt
    Write-Output "Writing to System Host File...." -ForegroundColor White -BackgroundColor Black
    Try {
        Write-Output "" | Out-File -Encoding ASCII $hosts_file
        Get-Content $PSScriptRoot/Files/hosts.txt | Out-File -Encoding ASCII -Append $hosts_file
        Write-Output "Write Successful.." -ForegroundColor Green -BackgroundColor Black
    }
    Catch {
        Write-Output "Error writing to System Host File...." -ForegroundColor Red -BackgroundColor Black
    }    
}
Else {
    # Test if web access to the repo is available, if so download latest version of config
    # First we create the request.
    $HTTP_Request2 = [System.Net.WebRequest]::Create('http://sbc.io/hosts/hosts')
    # We then get a response from the site.
    $HTTP_Response2 = $HTTP_Request.GetResponse()
    # We then get the HTTP code as an integer.
    $HTTP_Status2 = [int]$HTTP_Response.StatusCode
    If ($HTTP_Status2 -eq 200) {
        Write-Host "Repo Access is Available. Downloading Latest Host File" -ForegroundColor White -BackgroundColor Black
        Invoke-WebRequest -Uri "http://sbc.io/hosts/hosts" -OutFile $PSScriptRoot/Files/hosts.txt
        Write-Output "Writing to System Host File...." -ForegroundColor White -BackgroundColor Black
        Try {
            Write-Output "" | Out-File -Encoding ASCII $hosts_file
            Get-Content $PSScriptRoot/Files/hosts.txt | Out-File -Encoding ASCII -Append $hosts_file
            Write-Output "Write Successful.." -ForegroundColor Green -BackgroundColor Black
        }
        Catch {
            Write-Output "Error writing to System Host File...." -ForegroundColor Red -BackgroundColor Black
        }        
    }
    Else {
        Write-Host "Unable to download host file. Please check your internet and proxy settings...." -ForegroundColor Red -BackgroundColor Black
        Write-Host "Continuing with Local Copy..." -ForegroundColor White -BackgroundColor Black
        Try {
            Write-Output "" | Out-File -Encoding ASCII $hosts_file
            Get-Content $PSScriptRoot/Files/hosts.txt | Out-File -Encoding ASCII -Append $hosts_file
            Write-Output "Write Successful.." -ForegroundColor Green -BackgroundColor Black
        }
        Catch {
            Write-Output "Error writing to System Host File...." -ForegroundColor Red -BackgroundColor Black
        } 
    }
    # Finally, we clean up the http request by closing it.
    If ($HTTP_Response -eq $null) { } 
    Else { $HTTP_Response.Close() }
}
# Finally, we clean up the http request by closing it.
If ($HTTP_Response -eq $null) { } 
Else { $HTTP_Response.Close() }
