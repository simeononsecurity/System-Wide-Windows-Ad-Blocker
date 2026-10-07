# System-Wide Windows Ad Blocker

Apply a validated StevenBlack hosts list inside a managed section of the Windows hosts file. Preserve existing custom mappings and retain an exact original backup.

## Requirements

Run from an elevated Windows PowerShell 5.1 or PowerShell 7 terminal. Extract the repository before execution. Test DNS resolution and required applications on a disposable Windows system before deployment.

## Apply or preview

```powershell
.\sos-system-wide-windows-ad-block.ps1 -WhatIf
.\sos-system-wide-windows-ad-block.ps1
```

The default list uses HTTPS. Redirects are rejected. Empty lists, malformed records, invalid domain syntax, and records directing blocked domains to non-loopback addresses are rejected before file changes. Localhost records are ignored. DNS names containing underscores are accepted because upstream includes them.

For a reviewed offline list:

```powershell
.\sos-system-wide-windows-ad-block.ps1 -ListPath C:\Downloads\hosts.txt
```

Custom mappings outside `BEGIN SOS AD BLOCKER` and `END SOS AD BLOCKER` remain intact and take precedence over list entries. Updates replace only the managed section. No DNS service or .NET registry changes are applied. Hosts files must use ASCII or UTF-8.

The default backup is `%ProgramData%\SoS-Hosts\backup.json`. Use `-BackupPath` to select another local location and reuse the same path for updates and restoration. Backups contain original bytes and integrity hashes. Keep them protected.

## Restore

```powershell
.\sos-system-wide-windows-ad-block.ps1 -Mode Restore -WhatIf
.\sos-system-wide-windows-ad-block.ps1 -Mode Restore
```

Restore recovers the exact original file, including its line endings. If another application or user changed the hosts file after application, the script stops instead of discarding those edits. Preserve and reconcile edits before retrying. The backup is removed only after successful restoration.

Earlier versions overwrote the full hosts file. This release cannot recover custom entries already lost by an earlier installation. Use a pre-existing backup for those entries.

## Tests

```powershell
pwsh -NoProfile -File tests/Regression.ps1
```

Tests use temporary files, never the system hosts file. They cover custom mappings, repeated updates, original-byte recovery, WhatIf, invalid input, HTTP rejection, and the bundled upstream-format list. CI runs Windows PowerShell 5.1 and PowerShell 7. Native DNS behavior and large-list performance require separate Windows acceptance tests.
