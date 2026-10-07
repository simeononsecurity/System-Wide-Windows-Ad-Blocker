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
