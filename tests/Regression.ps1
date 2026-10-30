$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../HostsBlocker.psm1') -Force
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
function Throws([scriptblock]$Action) { $failed=$false; try { & $Action } catch { $failed=$true }; Assert $failed 'Expected failure' }
$root = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$null = New-Item -ItemType Directory $root
try {
    $hosts = Join-Path $root 'hosts'
    $backup = Join-Path $root 'backup.json'
    $list = Join-Path $root 'list.txt'
    $initial = [Text.Encoding]::UTF8.GetBytes("127.0.0.1 localhost`r`n10.0.0.2 custom.example`r`n")
    [IO.File]::WriteAllBytes($hosts,$initial)
    [IO.File]::WriteAllText($list,"255.255.255.255 broadcasthost`nff02::1 ip6-allnodes`n0.0.0.0 ad.example`n0.0.0.0 custom.example`n0.0.0.0 ad.example")
    Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -ListPath $list -WhatIf
    Assert (-not (Test-Path $backup)) 'WhatIf wrote backup'
    Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -ListPath $list
    $first = [IO.File]::ReadAllText($hosts)
    Assert ($first.Contains('10.0.0.2 custom.example')) 'Custom entry lost'
    Assert (-not $first.Contains('0.0.0.0 custom.example')) 'Custom mapping overridden'
    Assert ([regex]::Matches($first,'0.0.0.0 ad.example').Count -eq 1) 'Duplicate domain'
    Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -ListPath $list
    Assert ([IO.File]::ReadAllText($hosts) -eq $first) 'Update is not idempotent'
    [IO.File]::WriteAllText($hosts,$first+"# user edit`n")
    Throws { Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -Mode Restore }
    [IO.File]::WriteAllText($hosts,$first)
    Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -Mode Restore
    Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($hosts)) -eq [Convert]::ToBase64String($initial)) 'Restore changed original bytes'

    if ($env:OS -eq 'Windows_NT') {
        # A transient sharing violation should be retried and recover without
        # requiring the user to rerun Restore manually.
        $attempts = [pscustomobject]@{ Count = 0 }
        $attemptCount = & (Get-Module HostsBlocker) {
            param($state)
            Invoke-FileOperationWithRetry -Path 'isolated retry test' -Operation 'test retry handling for' -MaxAttempts 3 -RetryDelayMilliseconds 0 -Action {
                $state.Count++
                if ($state.Count -eq 1) { throw [ComponentModel.Win32Exception]::new(32) }
            }
            return $state.Count
        } $attempts
        Assert ($attemptCount -eq 2) 'Transient sharing violation was not retried'

        # A locked hosts file must produce a useful error and leave recovery data intact.
        Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -ListPath $list
        $lockedBytes = [IO.File]::ReadAllBytes($hosts)
        $backupJson = [IO.File]::ReadAllText($backup)
        # Existing reads are allowed, but the held handle does not share write
        # access, reproducing a reader that prevents replacing the hosts file.
        $lock = [IO.File]::Open($hosts, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $lockMessage = ''
            try { Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -Mode Restore }
            catch { $lockMessage = $_.Exception.Message }
            Assert ($lockMessage -match 'exclusive lock') 'Locked restore did not explain the possible exclusive lock'
            Assert (Test-Path -LiteralPath $backup) 'Locked restore removed its recovery backup'
            Assert ([IO.File]::ReadAllText($backup) -eq $backupJson) 'Locked restore changed its recovery backup'
        } finally { $lock.Dispose() }
        Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($hosts)) -eq [Convert]::ToBase64String($lockedBytes)) 'Locked restore changed hosts bytes'
        Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -Mode Restore
        Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($hosts)) -eq [Convert]::ToBase64String($initial)) 'Retry after releasing the lock did not restore original bytes'
        Assert (-not (Test-Path -LiteralPath $backup)) 'Successful retry did not remove the verified backup'

        # Unknown content, even a prefix of the backup, must not be treated as
        # an interrupted restore without reliable evidence of that write.
        Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -ListPath $list
        $appliedBytes = [IO.File]::ReadAllBytes($hosts)
        [IO.File]::WriteAllBytes($hosts, [byte[]]$initial[0..5])
        Throws { Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -Mode Restore }
        Assert (Test-Path -LiteralPath $backup) 'Restore discarded recovery data after detecting an unknown prefix'
        Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($hosts)) -eq [Convert]::ToBase64String([byte[]]$initial[0..5])) 'Restore overwrote unknown prefix content'
        [IO.File]::WriteAllBytes($hosts, $appliedBytes)
        Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -Mode Restore
        Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($hosts)) -eq [Convert]::ToBase64String($initial)) 'Restore failed after preserving unknown prefix content'

        # Restore must clear blocking attributes for the write and put them back afterward.
        Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -ListPath $list
        $attributes = [IO.FileAttributes]::ReadOnly -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System
        [IO.File]::SetAttributes($hosts, $attributes)
        Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -Mode Restore
        Assert ([IO.File]::GetAttributes($hosts) -eq $attributes) 'Restore did not preserve hosts file attributes'
        Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($hosts)) -eq [Convert]::ToBase64String($initial)) 'Restore with file attributes changed original bytes'
    }

    foreach ($bad in @('<html>error</html>','1.2.3.4 ads.example','0.0.0.0 ../../bad','')) {
        [IO.File]::WriteAllText($list,$bad)
        Throws { Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -ListPath $list }
        Assert (-not (Test-Path $backup)) 'Invalid input created backup'
    }
    Throws { Invoke-HostsBlocker -HostsPath $hosts -BackupPath $backup -ListUri 'http://example.com/list' }
    # Validate the actual bundled upstream-format list without changing any system file.
    $entries = @(ConvertTo-BlockEntries ([IO.File]::ReadAllText((Join-Path $PSScriptRoot '../Files/hosts.txt'))))
    Assert ($entries.Count -gt 1000) 'Bundled upstream fixture did not parse'
    Write-Output 'PASS: hosts isolation, custom mappings, update, exact restore, WhatIf and malformed input'
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
