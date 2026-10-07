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
    if ((Get-Item -LiteralPath $HostsPath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Hosts symlinks are not supported.' }
    $original = [IO.File]::ReadAllBytes($HostsPath)
    $saved = $null
    if (Test-Path -LiteralPath $BackupPath) {
        $saved = Get-Content -LiteralPath $BackupPath -Raw | ConvertFrom-Json
        if ($saved.Version -ne 1 -or $saved.HostsPath -ne $HostsPath) { throw 'Backup belongs to a different hosts file.' }
        $backupBytes = [Convert]::FromBase64String($saved.Original)
        if ((Get-BytesHash $backupBytes) -ne $saved.OriginalHash) { throw 'Backup integrity check failed.' }
    }
    if ($Mode -eq 'Restore') {
        if (-not $saved) { throw 'No backup exists. Legacy changes require manual recovery.' }
        $hash = Get-BytesHash $original
        if ($hash -ne $saved.AppliedHash -and $hash -ne $saved.OriginalHash -and $hash -ne $saved.PreviousHash) {
            throw 'Hosts file changed after application. Preserve those edits before exact restoration.'
        }
        if ($PSCmdlet.ShouldProcess($HostsPath, 'Restore exact original hosts bytes')) {
            Write-AtomicBytes $HostsPath $backupBytes
            if ((Get-BytesHash ([IO.File]::ReadAllBytes($HostsPath))) -ne $saved.OriginalHash) { throw 'Restore verification failed.' }
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
