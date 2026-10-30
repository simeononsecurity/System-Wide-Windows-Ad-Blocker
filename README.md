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

On Windows, restore temporarily clears read-only, hidden, and system attributes, then writes through the existing file without requiring delete/rename access. It retries common sharing, lock, and access-denied errors and reports when another process or security product may be holding the file. If the current contents do not match a known managed state, restore keeps the backup and refuses to overwrite them. A non-retryable disk or device error during an in-place write could leave partial contents; in that case the backup remains available for manual recovery.

Earlier versions overwrote the full hosts file. This release cannot recover custom entries already lost by an earlier installation. Use a pre-existing backup for those entries.

## Tests

```powershell
pwsh -NoProfile -File tests/Regression.ps1
```

The regression suite uses temporary files, never the system hosts file. It covers custom mappings, repeated updates, original-byte recovery, WhatIf, invalid input, HTTP rejection, and the bundled upstream-format list. CI runs Windows PowerShell 5.1 and PowerShell 7. Large-list performance still requires separate Windows acceptance testing.

## Windows DNS integration test

The `Windows DNS integration` workflow applies the complete bundled list on a fresh GitHub-hosted Windows VM, then checks several block-list domains and four explicit non-blocklisted controls (`example.com`, `github.com`, `iana.org`, and `www.microsoft.com`) with `.NET System.Net.Dns.GetHostAddresses` (the Windows OS resolver, which honors the hosts file). It verifies each control's A record before, during, and after Apply/Restore, records returned A/AAAA addresses and elapsed time, and probes direct A and optional AAAA records for baseline health. Any CNAME targets returned for controls are checked against the installed list. It flushes the DNS client cache with bounded `ipconfig /flushdns` processes, restores the original hosts bytes and attributes in `finally`, verifies that recovery, and checks the sample domains again. A bounded block-list sample avoids coupling the assertion to domains that no longer have public DNS records; AAAA answers are observed but not required for network reachability.

This test changes only the disposable hosted runner. A guard prevents it from running on a developer machine or self-hosted runner. It uploads a seven-day log artifact. Exit code 1 indicates a script or harness regression; exit code 2 indicates an external DNS/network preflight or resolver environment failure, so that condition is distinguishable from the script assertions. The test exercises normal Windows file sharing and the runner's DNS client; it does not simulate third-party antivirus/minifilter locks or desktop-machine policy.

Windows containers are not used for this check: their container filesystem and network endpoint are isolated, so the script would modify the container's hosts file and use container DNS settings rather than the disposable Windows runner's hosts file and DNS client. Binding the host hosts file into a container would defeat the isolation requirement. The GitHub-hosted `windows-latest` VM is the safe environment for this end-to-end check.
