# System-Wide-Windows-Ad-Blocker
Block Ads, Tracking, and Telemetry System Wide 

## Description:
This script blocks Telemetry related domains via the hosts file and related IPs via Windows Firewall.

**Notes:**
- Adding these domains may break certain software like iTunes or Skype
- Entries related to Akamai have been reported to cause issues with Widevine DRM

### Lists Used:
- [EasyList](https://easylist.to/easylist/easylist.txt) / [JustDomains - EasyList](https://justdomains.github.io/blocklists/lists/easylist-justdomains.txt)
- [Easy Privacy](https://easylist.to/easylist/easyprivacy.txt) [JustDomains - EasyPrivacy](https://justdomains.github.io/blocklists/lists/easyprivacy-justdomains.txt)
- [NoCoin Filter List](https://github.com/hoshsadiq/adblock-nocoin-list/) / [JustDomains - NoCoin Filter List](https://justdomains.github.io/blocklists/lists/nocoin-justdomains.txt)
- [AdGuard DNS filter](https://github.com/AdguardTeam/AdguardSDNSFilter) / [JustDomains - AdGuard Simplified Domain Names Filter](https://justdomains.github.io/blocklists/lists/adguarddns-justdomains.txt)
- [YoYo Lists](https://pgl.yoyo.org/adservers/serverlist.php)
- [Peter Lowe’s ad/tracking/malware servers](https://pgl.yoyo.org/adservers/policy.php)

### Example:
```powershell
.\"sos-system-wide-windows-ad-block.ps1"
```
