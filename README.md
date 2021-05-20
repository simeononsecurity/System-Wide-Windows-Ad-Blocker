# System-Wide-Windows-Ad-Blocker
This script blocks Telemetry, Ads, and Malware related domains via the hosts file.

*We are seeking all comments and concerns for this repo. Please submit an [issue](https://github.com/simeononsecurity/System-Wide-Windows-Ad-Blocker/issues) with any information you might have.*

### Lists Used:
- [StevenBlack/hosts - adware + malware](https://github.com/StevenBlack/hosts)

### Example:
#### Manual install:
**The script may be launched from the extracted GitHub download like this:**
```powershell
.\sos-system-wide-windows-ad-block.ps1
```
#### Automated install:
Run the latest version of the script automatically (currently unworking.. please run manual install):
```powershell
iwr -useb 'https://raw.githubusercontent.com/simeononsecurity/System-Wide-Windows-Ad-Blocker/main/sos-system-wide-windows-ad-block.ps1' | iex
```
