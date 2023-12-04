# System-Wide-Windows-Ad-Blocker

[![VirusTotal Scan](https://github.com/simeononsecurity/System-Wide-Windows-Ad-Blocker/actions/workflows/virustotal.yml/badge.svg)](https://github.com/simeononsecurity/System-Wide-Windows-Ad-Blocker/actions/workflows/virustotal.yml)

This script is a Windows PowerShell script that downloads and applies the "StevenBlack/hosts" file to the system's "hosts" file, which can be used to block certain domains/websites by mapping them to an IP address of your choice (usually the IP address of the local machine). The script checks the internet connection and proxy settings, and tries downloading the latest version of the "hosts" file from two different sources: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" and "http://sbc.io/hosts/hosts". If the download fails, the script continues with a local copy of the "hosts" file. The script requires elevated privileges to run and modifies the ".NETFramework" registry key to use only the latest version of the .NET framework.

*We are seeking all comments and concerns for this repo. Please submit an [issue](https://github.com/simeononsecurity/System-Wide-Windows-Ad-Blocker/issues) with any information you might have.*

## Known Issues
We've so far been unable to replicate the issue, but on some systems a issue occurs from the hosts file being too large. This causes windows to be unable to resolve any domain at all.
We suspect this is caused by low spec system performance. If this is you, please revert the changes with the guide below and submit an issue.

### Lists Used:
- [StevenBlack/hosts - adware + malware](https://github.com/StevenBlack/hosts)

### Example:
#### Manual install:
**The script may be launched from the extracted GitHub download like this:**
```powershell
.\sos-system-wide-windows-ad-block.ps1
```
#### Automated install:
Run the latest version of the script automatically:
```powershell
iwr -useb 'https://simeononsecurity.ch/scripts/soswindowsadblocker.ps1' | iex
```
#### Removal
https://github.com/simeononsecurity/System-Wide-Windows-Ad-Blocker/issues/1

## Learn more about [Blocking Windows Ads and Trackers](https://simeononsecurity.ch/github/System-Wide-Windows-Ad-Blocker)
<a href="https://simeononsecurity.com" target="_blank" rel="noopener noreferrer">
  <h2>Explore the World of Cybersecurity</h2>
</a>
<a href="https://simeononsecurity.com" target="_blank" rel="noopener noreferrer">
  <img src="https://simeononsecurity.com/img/banner.png" alt="SimeonOnSecurity Logo" width="300" height="300">
</a>

### Links:
- #### [github.com/simeononsecurity](https://github.com/simeononsecurity)
- #### [simeononsecurity.com](https://simeononsecurity.com)
