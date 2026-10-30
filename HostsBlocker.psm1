Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Begin = '# BEGIN SOS AD BLOCKER'
$script:End = '# END SOS AD BLOCKER'

function Get-BytesHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function ConvertTo-BlockEntries([string]$Text) {
    if ($Text.Length -gt 10MB -or $Text.Contains([char]0)) { throw 'Invalid block list size or encoding.' }
    $entries = New-Object 'System.Collections.Generic.SortedSet[string]'
    foreach ($line in ($Text -split '\r?\n')) {
        $clean = ($line -split '#', 2)[0].Trim()
        if (-not $clean) { continue }
        $parts = $clean -split '\s+'
        if ($parts.Count -lt 2) { throw 'Hosts record requires an address and a name.' }
        $localNames = @('localhost','localhost.localdomain','local','broadcasthost','ip6-localhost','ip6-loopback','ip6-localnet','ip6-mcastprefix','ip6-allnodes','ip6-allrouters','ip6-allhosts','0.0.0.0')
        if (@($parts[1..($parts.Count - 1)] | Where-Object { $_ -notin $localNames }).Count -eq 0) { continue }
        if ($parts[0] -notin @('0.0.0.0','127.0.0.1','::','::1')) {
            throw "Invalid hosts-list record: $clean"
        }
        foreach ($domain in $parts[1..($parts.Count - 1)]) {
            if ($domain -in @('localhost','localhost.localdomain','local','broadcasthost','ip6-localhost','ip6-loopback','ip6-localnet','ip6-mcastprefix','ip6-allnodes','ip6-allrouters','ip6-allhosts')) { continue }
            if ($domain.Length -gt 253 -or $domain -notmatch '^(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$') {
                throw "Invalid domain: $domain"
            }
            $null = $entries.Add('0.0.0.0 ' + $domain.ToLowerInvariant())
        }
    }
    if ($entries.Count -eq 0) { throw 'Block list contains no valid domains.' }
    return @($entries)
}

function Write-AtomicBytes([string]$Path, [byte[]]$Bytes) {
    $temp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllBytes($temp, $Bytes)
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temp, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temp, $Path) }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}

function Invoke-FileOperationWithRetry {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][scriptblock]$Action,
        [ValidateRange(1, 10)][int]$MaxAttempts = 4,
        [ValidateRange(0, 5000)][int]$RetryDelayMilliseconds = 250
    )
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            & $Action
            return
        } catch {
            $rootFailure = $_.Exception
            $failure = $rootFailure
            $win32Code = 0
            while ($failure) {
                $candidate = $failure.HResult -band 0xFFFF
                if ($candidate -in @(5, 32, 33)) { $win32Code = $candidate; break }
                if ($failure -is [ComponentModel.Win32Exception] -and $failure.NativeErrorCode -in @(5, 32, 33)) {
                    $win32Code = $failure.NativeErrorCode
                    break
                }
                $failure = $failure.InnerException
            }
            if ($win32Code -eq 0) { throw }
            if ($attempt -lt $MaxAttempts) {
                Start-Sleep -Milliseconds ($RetryDelayMilliseconds * $attempt)
                continue
            }
            if ($win32Code -in @(32, 33)) {
                $detail = 'Windows reported a sharing or lock violation. Another process or security product may hold an exclusive lock.'
            } else {
                $detail = 'Windows reported access denied. Check permissions, file attributes, and whether another process or security product holds an exclusive lock.'
            }
            $message = "Unable to $Operation '$Path' after $MaxAttempts attempts. $detail Check the file and retry after the lock or access problem is resolved. If a restore backup exists, it remains available and is removed only after the restored file passes integrity verification."
            throw [IO.IOException]::new($message, $rootFailure)
        }
    }
}

function Read-FileBytesWithRetry([string]$Path, [string]$Operation = 'read') {
    $bytes = Invoke-FileOperationWithRetry -Path $Path -Operation $Operation -Action { [IO.File]::ReadAllBytes($Path) }
    return ,([byte[]]$bytes)
}

function Test-RestoreSourceState([byte[]]$Bytes, $Saved) {
    $hash = Get-BytesHash $Bytes
    $knownState = $hash -eq $Saved.AppliedHash -or $hash -eq $Saved.OriginalHash -or $hash -eq $Saved.PreviousHash
    return [bool]$knownState
}

function Read-StreamBytes([IO.Stream]$Stream) {
    if ($Stream.Length -gt [int]::MaxValue) { throw 'Hosts file is too large to verify safely.' }
    $bytes = New-Object 'byte[]' ([int]$Stream.Length)
    $Stream.Position = 0
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $Stream.Read($bytes, $offset, [Math]::Min(65536, $bytes.Length - $offset))
        if ($read -le 0) { throw 'Hosts file changed while it was being checked for restoration.' }
        $offset += $read
    }
    return ,$bytes
}

function Restore-FileBytes([string]$Path, [byte[]]$Bytes, [string]$ExpectedHash, $Saved) {
    $attributes = Invoke-FileOperationWithRetry -Path $Path -Operation 'read file attributes for' -Action { [IO.File]::GetAttributes($Path) }
    $attributesToClear = [IO.FileAttributes]::ReadOnly -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System
    $writeAttributes = $attributes -band (-bnot $attributesToClear)
    $attributesChanged = $writeAttributes -ne $attributes
    $stream = $null
    try {
        if ($attributesChanged) {
            Invoke-FileOperationWithRetry -Path $Path -Operation 'clear blocking file attributes on' -Action { [IO.File]::SetAttributes($Path, $writeAttributes) }
        }

        # Open the existing file for read/write without delete/rename access. The
        # handle blocks new writers while we recheck its bytes and do the restore.
        $stream = Invoke-FileOperationWithRetry -Path $Path -Operation 'open hosts file for restore at' -Action {
            [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
        }
        $current = Read-StreamBytes $stream
        if (-not (Test-RestoreSourceState -Bytes $current -Saved $Saved)) {
            throw 'Hosts file changed immediately before restoration. Preserve those edits; the recovery backup was retained.'
        }
        # Reset before every attempt so a transient I/O failure after truncation
        # can retry from the first byte while this handle still excludes writers.
        Invoke-FileOperationWithRetry -Path $Path -Operation 'write restored hosts bytes to' -Action {
            $stream.SetLength(0)
            $stream.Position = 0
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        }
        $stream.Dispose()
        $stream = $null

        $restored = Read-FileBytesWithRetry -Path $Path -Operation 'verify restored hosts file at'
        if ((Get-BytesHash $restored) -ne $ExpectedHash) { throw 'Restore verification failed; the recovery backup was retained.' }

        if ($attributesChanged) {
            Invoke-FileOperationWithRetry -Path $Path -Operation 'restore file attributes on' -Action { [IO.File]::SetAttributes($Path, $attributes) }
            $attributesChanged = $false
        }
        $restored = Read-FileBytesWithRetry -Path $Path -Operation 'verify restored hosts file at'
        if ((Get-BytesHash $restored) -ne $ExpectedHash) { throw 'Restore verification failed after restoring file attributes; the recovery backup was retained.' }
    } catch {
        $failure = $_
        $cleanupFailures = New-Object 'System.Collections.Generic.List[string]'
        if ($stream) {
            try { $stream.Dispose() }
            catch { $cleanupFailures.Add("Closing the hosts file handle failed: $($_.Exception.Message)") }
        }
        if ($attributesChanged) {
            try { Invoke-FileOperationWithRetry -Path $Path -Operation 'restore original file attributes on' -Action { [IO.File]::SetAttributes($Path, $attributes) } }
            catch { $cleanupFailures.Add("Restoring the original hosts file attributes failed: $($_.Exception.Message)") }
        }
        if ($cleanupFailures.Count -gt 0) {
            $cleanupDetail = $cleanupFailures -join ' '
            Write-Warning "Restore failed: $($failure.Exception.Message) Cleanup also failed: $cleanupDetail The recovery backup was retained for manual recovery."
        }
        throw $failure.Exception
    }
}

function Invoke-HostsBlocker {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$HostsPath,
        [Parameter(Mandatory)][string]$BackupPath,
        [ValidateSet('Apply','Restore')][string]$Mode = 'Apply',
        [string]$ListPath,
        [uri]$ListUri = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
    )
    $HostsPath = [IO.Path]::GetFullPath($HostsPath)
    $BackupPath = [IO.Path]::GetFullPath($BackupPath)
    if ($HostsPath -eq $BackupPath) { throw 'Backup path must differ from hosts path.' }
    if ((Get-Item -Force -LiteralPath $HostsPath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Hosts symlinks are not supported.' }
    $original = Read-FileBytesWithRetry -Path $HostsPath -Operation 'read hosts file at'
    $saved = $null
    if (Test-Path -LiteralPath $BackupPath) {
        $saved = Get-Content -LiteralPath $BackupPath -Raw | ConvertFrom-Json
        if ($saved.Version -ne 1 -or $saved.HostsPath -ne $HostsPath) { throw 'Backup belongs to a different hosts file.' }
        $backupBytes = [Convert]::FromBase64String($saved.Original)
        if ((Get-BytesHash $backupBytes) -ne $saved.OriginalHash) { throw 'Backup integrity check failed.' }
    }
    if ($Mode -eq 'Restore') {
        if (-not $saved) { throw 'No backup exists. Legacy changes require manual recovery.' }
        if (-not (Test-RestoreSourceState -Bytes $original -Saved $saved)) {
            throw 'Hosts file changed after application. Preserve those edits before exact restoration.'
        }
        if ($PSCmdlet.ShouldProcess($HostsPath, 'Restore exact original hosts bytes')) {
            $latest = Read-FileBytesWithRetry -Path $HostsPath -Operation 'recheck hosts file before restoring'
            if (-not (Test-RestoreSourceState -Bytes $latest -Saved $saved)) {
                throw 'Hosts file changed immediately before restoration. Preserve those edits; the recovery backup was retained.'
            }
            Restore-FileBytes -Path $HostsPath -Bytes $backupBytes -ExpectedHash $saved.OriginalHash -Saved $saved
            Remove-Item -LiteralPath $BackupPath
        }
        return
    }
    if ($saved -and (Get-BytesHash $original) -notin @($saved.AppliedHash, $saved.OriginalHash, $saved.PreviousHash)) { throw 'Hosts file changed outside the managed update. Preserve edits before continuing.' }
    if ($ListPath) { $list = [IO.File]::ReadAllText([IO.Path]::GetFullPath($ListPath)) }
    else {
        if ($ListUri.Scheme -ne 'https') { throw 'Only HTTPS list URLs are allowed.' }
        $response = Invoke-WebRequest -Uri $ListUri -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 0 -ErrorAction Stop
        $list = [string]$response.Content
    }
    $entries = @(ConvertTo-BlockEntries $list)
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $text = $utf8.GetString($original)
    if ($text.Contains([char]0)) { throw 'Hosts file must use ASCII or UTF-8 encoding.' }
    $beginCount = [regex]::Matches($text, '(?m)^# BEGIN SOS AD BLOCKER\r?$').Count
    $endCount = [regex]::Matches($text, '(?m)^# END SOS AD BLOCKER\r?$').Count
    if ($beginCount -ne $endCount -or $beginCount -gt 1) { throw 'Malformed managed block.' }
    if ($beginCount -and -not $saved) { throw 'Managed block exists without its backup.' }
    if ($beginCount) {
        $pattern = '(?ms)^# BEGIN SOS AD BLOCKER\r?\n.*?^# END SOS AD BLOCKER(?:\r?\n|$)'
        if (-not [regex]::IsMatch($text, $pattern)) { throw 'Invalid managed block order.' }
        $text = [regex]::Replace($text, $pattern, '')
    }
    $newline = "`r`n"
    if ($text.Contains("`n") -and -not $text.Contains("`r`n")) { $newline = "`n" }
    if ($text -and -not $text.EndsWith("`n")) { $text += $newline }
    # A user's existing domain mapping takes precedence over the downloaded list.
    $custom = @{}
    foreach ($line in ($text -split '\r?\n')) {
        $parts = (($line -split '#',2)[0].Trim() -split '\s+')
        if ($parts.Count -ge 2) { foreach ($domain in $parts[1..($parts.Count-1)]) { $custom[$domain] = $true } }
    }
    $entries = @($entries | Where-Object { -not $custom.ContainsKey(($_ -split ' ')[1]) })
    $newText = $text + $script:Begin + $newline + ($entries -join $newline) + $newline + $script:End + $newline
    $newBytes = $utf8.GetBytes($newText)
    if (-not $saved) {
        $saved = [pscustomobject]@{ Version = 1; HostsPath = $HostsPath; Original = [Convert]::ToBase64String($original); OriginalHash = (Get-BytesHash $original); AppliedHash = ''; PreviousHash = '' }
    }
    $saved.PreviousHash = Get-BytesHash $original
    $saved.AppliedHash = Get-BytesHash $newBytes
    if ($PSCmdlet.ShouldProcess($HostsPath, 'Back up hosts and replace the managed block')) {
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $BackupPath) -Force
        $jsonBytes = $utf8.GetBytes(($saved | ConvertTo-Json -Depth 5))
        Write-AtomicBytes $BackupPath $jsonBytes
        Write-AtomicBytes $HostsPath $newBytes
        if ((Get-BytesHash ([IO.File]::ReadAllBytes($HostsPath))) -ne $saved.AppliedHash) { throw 'Application verification failed.' }
        Write-Output "Applied $($entries.Count) entries. Original backup: $BackupPath"
    }
}
Export-ModuleMember -Function Invoke-HostsBlocker, ConvertTo-BlockEntries
