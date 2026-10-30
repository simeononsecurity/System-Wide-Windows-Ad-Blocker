#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ResolveName,
    [switch]$DnsProbe,
    [switch]$DnsTelemetry,
    [switch]$EmergencyRestore
)

$ErrorActionPreference = 'Stop'

function Read-DnsUInt16([byte[]]$Packet, [int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 1 -ge $Packet.Length) { throw 'DNS response ended inside a 16-bit field.' }
    return (([int]$Packet[$Offset] -shl 8) -bor [int]$Packet[$Offset + 1])
}

function Read-DnsName([byte[]]$Packet, [int]$Offset, [ref]$NextOffset) {
    $labels = New-Object 'System.Collections.Generic.List[string]'
    $position = $Offset
    $jumped = $false
    for ($steps = 0; $steps -lt 128; $steps++) {
        if ($position -lt 0 -or $position -ge $Packet.Length) { throw 'DNS response contained an invalid name offset.' }
        $length = [int]$Packet[$position]
        if (($length -band 0xC0) -eq 0xC0) {
            if ($position + 1 -ge $Packet.Length) { throw 'DNS response ended inside a name pointer.' }
            $pointer = (($length -band 0x3F) -shl 8) -bor [int]$Packet[$position + 1]
            if (-not $jumped) { $NextOffset.Value = $position + 2; $jumped = $true }
            $position = $pointer
            continue
        }
        if ($length -eq 0) {
            if (-not $jumped) { $NextOffset.Value = $position + 1 }
            break
        }
        if ($length -gt 63 -or $position + $length -ge $Packet.Length) { throw 'DNS response contained an invalid label.' }
        $position++
        $labels.Add([Text.Encoding]::ASCII.GetString($Packet, $position, $length))
        $position += $length
    }
    if ($steps -ge 128) { throw 'DNS response name compression loop exceeded its bound.' }
    return ($labels -join '.')
}

function Write-QueryStartedMarker {
    $markerPath = $env:SOS_DNS_E2E_QUERY_STARTED_MARKER
    if ($markerPath) { [IO.File]::WriteAllText($markerPath, 'started', [Text.Encoding]::ASCII) }
}

# The resolver child is deliberately a separate Windows PowerShell process so
# the parent can enforce a hard timeout around the OS hostname-resolution API.
if ($ResolveName) {
    $name = $env:SOS_DNS_E2E_RESOLVE_NAME
    if ($name -notmatch '^(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$') {
        [Console]::Error.WriteLine('Resolver received an invalid DNS name.')
        exit 64
    }
    try {
        Write-QueryStartedMarker
        $addresses = @([System.Net.Dns]::GetHostAddresses($name) | ForEach-Object { $_.IPAddressToString })
        if ($addresses.Count -eq 0) {
            [Console]::Error.WriteLine('The OS resolver returned no addresses.')
            exit 2
        }
        [Console]::Out.WriteLine(($addresses -join ','))
        exit 0
    } catch {
        [Console]::Error.WriteLine('OS resolver query failed.')
        exit 2
    }
}

# This DNS-only query is used only to diagnose network availability. All
# hosts-file assertions use GetHostAddresses above, which honors the local file.
if ($DnsProbe) {
    $name = $env:SOS_DNS_E2E_RESOLVE_NAME
    $server = $env:SOS_DNS_E2E_DNS_SERVER
    $recordType = $env:SOS_DNS_E2E_RECORD_TYPE
    if ($name -notmatch '^(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$' -or -not $server -or $recordType -notin @('A','AAAA')) {
        [Console]::Error.WriteLine('DNS health probe received an invalid name or server.')
        exit 64
    }
    try {
        # Send a bounded DNS packet directly over UDP. This deliberately avoids
        # Windows DnsClient APIs so it can distinguish an OS resolver stall
        # from a real loss of reachability to the configured DNS server.
        $identifier = New-Object 'byte[]' 2
        $random = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $random.GetBytes($identifier) } finally { $random.Dispose() }
        $query = New-Object 'System.Collections.Generic.List[byte]'
        $query.Add($identifier[0]); $query.Add($identifier[1])
        $query.Add(1); $query.Add(0) # recursion desired
        $query.Add(0); $query.Add(1) # one question
        $query.AddRange([byte[]]@(0,0,0,0,0,0))
        foreach ($label in $name.TrimEnd('.').Split('.')) {
            $labelBytes = [Text.Encoding]::ASCII.GetBytes($label)
            $query.Add([byte]$labelBytes.Length)
            $query.AddRange($labelBytes)
        }
        $query.Add(0)
        $queryType = if ($recordType -eq 'A') { 1 } else { 28 }
        $query.Add([byte](($queryType -shr 8) -band 0xFF)); $query.Add([byte]($queryType -band 0xFF))
        $query.Add(0); $query.Add(1) # IN class
        $queryBytes = $query.ToArray()

        $udp = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $udp.Client.ReceiveTimeout = 4500
            $endpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Parse($server), 53)
            $udp.Connect($endpoint)
            $null = $udp.Send($queryBytes, $queryBytes.Length)
            Write-QueryStartedMarker
            $remoteEndpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
            $response = $udp.Receive([ref]$remoteEndpoint)
        } finally { $udp.Dispose() }

        if ($response.Length -lt 12) { throw 'DNS response was shorter than its header.' }
        if ($response[0] -ne $identifier[0] -or $response[1] -ne $identifier[1]) { throw 'DNS response identifier did not match the query.' }
        $responseFlags = Read-DnsUInt16 $response 2
        if (($responseFlags -band 0x0200) -ne 0) { throw 'DNS UDP response was truncated.' }
        if (($responseFlags -band 0x000F) -ne 0) { throw 'DNS server returned an unsuccessful response code.' }
        $questionCount = Read-DnsUInt16 $response 4
        $answerCount = Read-DnsUInt16 $response 6
        $offset = 12
        for ($questionIndex = 0; $questionIndex -lt $questionCount; $questionIndex++) {
            $nextOffset = $offset
            $null = Read-DnsName -Packet $response -Offset $offset -NextOffset ([ref]$nextOffset)
            $offset = $nextOffset + 4
            if ($offset -gt $response.Length) { throw 'DNS response ended inside its question.' }
        }
        $addresses = New-Object 'System.Collections.Generic.List[string]'
        $cnameTargets = New-Object 'System.Collections.Generic.List[string]'
        for ($answerIndex = 0; $answerIndex -lt $answerCount; $answerIndex++) {
            $nextOffset = $offset
            $null = Read-DnsName -Packet $response -Offset $offset -NextOffset ([ref]$nextOffset)
            $offset = $nextOffset
            if ($offset + 10 -gt $response.Length) { throw 'DNS response ended inside an answer header.' }
            $answerType = Read-DnsUInt16 $response $offset
            $offset += 2 # type
            $answerClass = Read-DnsUInt16 $response $offset
            $offset += 6 # class and TTL
            $dataLength = Read-DnsUInt16 $response $offset
            $offset += 2
            $dataOffset = $offset
            if ($dataOffset + $dataLength -gt $response.Length) { throw 'DNS response ended inside answer data.' }
            if ($answerClass -eq 1 -and $answerType -eq 1 -and $dataLength -eq 4) {
                $addresses.Add(([Net.IPAddress]::new([byte[]]$response[$dataOffset..($dataOffset + 3)])).IPAddressToString)
            } elseif ($answerClass -eq 1 -and $answerType -eq 28 -and $dataLength -eq 16) {
                $addresses.Add(([Net.IPAddress]::new([byte[]]$response[$dataOffset..($dataOffset + 15)])).IPAddressToString)
            } elseif ($answerClass -eq 1 -and $answerType -eq 5) {
                $cnameNextOffset = $dataOffset
                $target = Read-DnsName -Packet $response -Offset $dataOffset -NextOffset ([ref]$cnameNextOffset)
                $cnameTargets.Add($target.TrimEnd('.').ToLowerInvariant())
            }
            $offset = $dataOffset + $dataLength
        }
        $addresses = @($addresses | Sort-Object -Unique)
        $cnameTargets = @($cnameTargets | Sort-Object -Unique)
        if ($addresses.Count -eq 0) {
            [Console]::Error.WriteLine("The configured DNS server returned no $recordType records.")
            exit 2
        }
        [Console]::Out.WriteLine('ADDRESSES=' + ($addresses -join ','))
        [Console]::Out.WriteLine('CNAMES=' + ($cnameTargets -join ','))
        exit 0
    } catch {
        [Console]::Error.WriteLine('Direct DNS health query failed.')
        exit 2
    }
}

if ($DnsTelemetry) {
    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='Dnscache'" -ErrorAction Stop
        if (-not $service -or -not $service.ProcessId) {
            [Console]::Out.WriteLine('STATUS=Unavailable;REASON=Dnscache service process is not running.')
            exit 0
        }
        $process = Get-Process -Id $service.ProcessId -ErrorAction Stop
        $cpuSeconds = if ($null -eq $process.CPU) { 'unavailable' } else { [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0:F3}', $process.CPU) }
        [Console]::Out.WriteLine(('STATUS=OK;SERVICE_STATE={0};PID={1};CPU_SECONDS={2};WORKING_SET_BYTES={3};THREADS={4};HANDLES={5}' -f $service.State, $service.ProcessId, $cpuSeconds, $process.WorkingSet64, $process.Threads.Count, $process.HandleCount))
        exit 0
    } catch {
        [Console]::Out.WriteLine('STATUS=Unavailable;REASON=Read-only Dnscache telemetry could not be collected.')
        exit 0
    }
}

# Last-resort cleanup is permitted only in the same guarded disposable hosted
# runner. It is used only if the production restore fails, and any such failure
# still fails the test even when this emergency cleanup succeeds.
if ($EmergencyRestore) {
    if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
        [Console]::Error.WriteLine('Emergency restore is restricted to a GitHub-hosted Windows runner.')
        exit 64
    }
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Emergency restore requires the hosted runner administrator token.' }
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        $snapshotPath = $env:SOS_DNS_E2E_ORIGINAL_SNAPSHOT
        if (-not (Test-Path -LiteralPath $snapshotPath -PathType Leaf)) { throw 'Original hosts snapshot is missing.' }
        $expectedHash = $env:SOS_DNS_E2E_ORIGINAL_HASH
        $originalAttributes = [IO.FileAttributes][int]$env:SOS_DNS_E2E_ORIGINAL_ATTRIBUTES
        $bytes = [IO.File]::ReadAllBytes($snapshotPath)
        $attributesToClear = [IO.FileAttributes]::ReadOnly -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System
        $writeAttributes = $originalAttributes -band (-bnot $attributesToClear)
        [IO.File]::SetAttributes($hostsPath, $writeAttributes)
        $restored = $false
        for ($attempt = 1; $attempt -le 4; $attempt++) {
            $stream = $null
            try {
                $stream = [IO.File]::Open($hostsPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
                $stream.SetLength(0)
                $stream.Position = 0
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Flush($true)
                $restored = $true
                break
            } catch {
                if ($attempt -eq 4) { throw }
                Start-Sleep -Milliseconds (250 * $attempt)
            } finally {
                if ($stream) { $stream.Dispose() }
            }
        }
        if (-not $restored) { throw 'Emergency in-place restore exhausted its retries.' }
        [IO.File]::SetAttributes($hostsPath, $originalAttributes)
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $actualHash = ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($hostsPath)))).Replace('-', '') }
        finally { $sha.Dispose() }
        if ($actualHash -ne $expectedHash) { throw "Emergency restore integrity check failed: expected $expectedHash, got $actualHash." }
        exit 0
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
}

$script:LogPath = Join-Path $env:RUNNER_TEMP 'dns-integration.log'
$script:SummaryPath = Join-Path $env:RUNNER_TEMP 'dns-integration-summary.md'
$script:ScriptFailures = New-Object 'System.Collections.Generic.List[string]'
$script:EnvironmentFailures = New-Object 'System.Collections.Generic.List[string]'
$script:HostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$script:BackupPath = Join-Path $env:RUNNER_TEMP 'dns-integration-backup.json'
$script:OriginalSnapshotPath = Join-Path $env:RUNNER_TEMP 'dns-integration-original-hosts.bin'
$script:HarnessPath = $PSCommandPath
$script:PowerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:ScriptPath = Join-Path $PSScriptRoot '..\sos-system-wide-windows-ad-block.ps1'
$script:ListPath = Join-Path $PSScriptRoot '..\Files\hosts.txt'
$script:ResolverTimeoutSeconds = 6
$script:ProcessTimeoutSeconds = 120
$script:FlushTimeoutSeconds = 15

function Write-Log([string]$Message) {
    $line = '[{0}] {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"), $Message
    [Console]::Out.WriteLine($line)
    [IO.File]::AppendAllText($script:LogPath, $line + [Environment]::NewLine, [Text.Encoding]::UTF8)
}

function Add-Failure([ValidateSet('SCRIPT','ENVIRONMENT')][string]$Class, [string]$Message) {
    if ($Class -eq 'SCRIPT') { $script:ScriptFailures.Add($Message) }
    else { $script:EnvironmentFailures.Add($Message) }
    Write-Log ("FAIL [{0}] {1}" -f $Class, $Message)
}

function Get-BytesHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Get-HostsFileState {
    try {
        if (-not (Test-Path -LiteralPath $script:HostsPath -PathType Leaf)) {
            return [pscustomobject]@{ Readable = $false; Hash = $null; Attributes = $null; Error = 'Hosts path is missing.' }
        }
        $bytes = [IO.File]::ReadAllBytes($script:HostsPath)
        return [pscustomobject]@{
            Readable = $true
            Hash = (Get-BytesHash $bytes)
            Attributes = [IO.File]::GetAttributes($script:HostsPath)
            Error = $null
        }
    } catch {
        return [pscustomobject]@{ Readable = $false; Hash = $null; Attributes = $null; Error = $_.Exception.Message }
    }
}

function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$Arguments,
        [Parameter(Mandatory)][ValidateRange(1, 600)][int]$TimeoutSeconds,
        [hashtable]$Environment = @{}
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FileName
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($key in $Environment.Keys) { $startInfo.EnvironmentVariables[$key] = [string]$Environment[$key] }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw "Could not start process '$FileName'." }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { Write-Log "Timed-out process could not be killed immediately: $($_.Exception.Message)" }
            $null = $process.WaitForExit(5000)
            $null = $stdoutTask.Wait(1000)
            $null = $stderrTask.Wait(1000)
            $stdout = if ($stdoutTask.IsCompleted) { $stdoutTask.Result } else { '<output unavailable after timeout>' }
            $stderr = if ($stderrTask.IsCompleted) { $stderrTask.Result } else { '<error output unavailable after timeout>' }
            return [pscustomobject]@{ TimedOut = $true; ExitCode = $null; StdOut = $stdout; StdErr = $stderr }
        }
        $null = $process.WaitForExit()
        return [pscustomobject]@{ TimedOut = $false; ExitCode = $process.ExitCode; StdOut = $stdoutTask.Result; StdErr = $stderrTask.Result }
    } finally {
        $process.Dispose()
    }
}

function Invoke-DnsFlush([string]$Phase) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $ipconfig = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
    $result = Invoke-BoundedProcess -FileName $ipconfig -Arguments '/flushdns' -TimeoutSeconds $script:FlushTimeoutSeconds
    $timer.Stop()
    Write-Log "DNS cache flush ($Phase): exit=$($result.ExitCode), timeout=$($result.TimedOut), elapsed-ms=$($timer.ElapsedMilliseconds)"
    if ($result.StdOut.Trim()) { Write-Log $result.StdOut.Trim() }
    if ($result.StdErr.Trim()) { Write-Log $result.StdErr.Trim() }
    return (-not $result.TimedOut -and $result.ExitCode -eq 0)
}

function Invoke-OsResolver([string]$Name) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -ResolveName' -f $script:HarnessPath
    $markerPath = Join-Path $env:RUNNER_TEMP ('dns-query-started-' + [guid]::NewGuid().ToString('N') + '.txt')
    $result = Invoke-BoundedProcess -FileName $script:PowerShellPath -Arguments $arguments -TimeoutSeconds $script:ResolverTimeoutSeconds -Environment @{ SOS_DNS_E2E_RESOLVE_NAME = $Name; SOS_DNS_E2E_QUERY_STARTED_MARKER = $markerPath }
    $timer.Stop()
    $queryStarted = Test-Path -LiteralPath $markerPath -PathType Leaf
    if ($queryStarted) { Remove-Item -LiteralPath $markerPath -Force }
    if ($result.TimedOut) {
        $detail = if ($queryStarted) { 'OS resolver query started but exceeded the timeout.' } else { 'Resolver child did not reach query start before the deadline.' }
        return [pscustomobject]@{ Status = 'Timeout'; Addresses = @(); DurationMilliseconds = $timer.ElapsedMilliseconds; QueryStarted = $queryStarted; Detail = $detail }
    }
    if ($result.ExitCode -ne 0) {
        return [pscustomobject]@{ Status = 'Failure'; Addresses = @(); DurationMilliseconds = $timer.ElapsedMilliseconds; QueryStarted = $queryStarted; Detail = $result.StdErr.Trim() }
    }
    $addresses = @($result.StdOut.Trim() -split ',' | Where-Object { $_ })
    if ($addresses.Count -eq 0) { return [pscustomobject]@{ Status = 'Failure'; Addresses = @(); DurationMilliseconds = $timer.ElapsedMilliseconds; QueryStarted = $queryStarted; Detail = 'OS resolver returned no address text.' } }
    return [pscustomobject]@{ Status = 'Success'; Addresses = $addresses; DurationMilliseconds = $timer.ElapsedMilliseconds; QueryStarted = $queryStarted; Detail = '' }
}

function Invoke-DnsClientTelemetry([string]$Phase) {
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -DnsTelemetry' -f $script:HarnessPath
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-BoundedProcess -FileName $script:PowerShellPath -Arguments $arguments -TimeoutSeconds $script:ResolverTimeoutSeconds
    $timer.Stop()
    if ($result.TimedOut) {
        Write-Log "Dnscache telemetry ($Phase): unavailable, collector timeout; elapsed-ms=$($timer.ElapsedMilliseconds)"
        return
    }
    $telemetry = ($result.StdOut -split '\r?\n' | Where-Object { $_ -like 'STATUS=*' } | Select-Object -First 1)
    if ($result.ExitCode -ne 0 -or -not $telemetry) { $telemetry = 'STATUS=Unavailable;REASON=Collector returned no data.' }
    Write-Log "Dnscache telemetry ($Phase): $telemetry; elapsed-ms=$($timer.ElapsedMilliseconds)"
}

function Get-ConfiguredDnsServer {
    foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($adapter.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up) { continue }
        try {
            foreach ($address in $adapter.GetIPProperties().DnsAddresses) {
                if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and -not [Net.IPAddress]::IsLoopback($address)) {
                    return $address.IPAddressToString
                }
            }
        } catch { Write-Log 'Could not read DNS server settings for an active adapter.' }
    }
    return $null
}

function Invoke-DirectDnsProbe([string]$Name, [string]$Server, [ValidateSet('A','AAAA')][string]$RecordType = 'A') {
    if (-not $Server) { return [pscustomobject]@{ Status = 'Unavailable'; Addresses = @(); CnameTargets = @(); DurationMilliseconds = 0; QueryStarted = $false; Detail = 'No configured IPv4 DNS server was found.' } }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -DnsProbe' -f $script:HarnessPath
    $markerPath = Join-Path $env:RUNNER_TEMP ('dns-query-started-' + [guid]::NewGuid().ToString('N') + '.txt')
    $result = Invoke-BoundedProcess -FileName $script:PowerShellPath -Arguments $arguments -TimeoutSeconds $script:ResolverTimeoutSeconds -Environment @{
        SOS_DNS_E2E_RESOLVE_NAME = $Name
        SOS_DNS_E2E_DNS_SERVER = $Server
        SOS_DNS_E2E_RECORD_TYPE = $RecordType
        SOS_DNS_E2E_QUERY_STARTED_MARKER = $markerPath
    }
    $timer.Stop()
    $queryStarted = Test-Path -LiteralPath $markerPath -PathType Leaf
    if ($queryStarted) { Remove-Item -LiteralPath $markerPath -Force }
    if ($result.TimedOut) {
        $detail = if ($queryStarted) { 'Direct DNS packet was sent but its response exceeded the timeout.' } else { 'DNS probe child did not send the query before the deadline.' }
        return [pscustomobject]@{ Status = 'Timeout'; Addresses = @(); CnameTargets = @(); DurationMilliseconds = $timer.ElapsedMilliseconds; QueryStarted = $queryStarted; Detail = $detail }
    }
    if ($result.ExitCode -ne 0) { return [pscustomobject]@{ Status = 'Failure'; Addresses = @(); CnameTargets = @(); DurationMilliseconds = $timer.ElapsedMilliseconds; QueryStarted = $queryStarted; Detail = $result.StdErr.Trim() } }
    $addressesLine = @($result.StdOut -split '\r?\n' | Where-Object { $_ -like 'ADDRESSES=*' } | Select-Object -First 1)
    $cnamesLine = @($result.StdOut -split '\r?\n' | Where-Object { $_ -like 'CNAMES=*' } | Select-Object -First 1)
    $addresses = if ($addressesLine.Count) { @($addressesLine[0].Substring(10) -split ',' | Where-Object { $_ }) } else { @() }
    $cnameTargets = if ($cnamesLine.Count -and $cnamesLine[0].Length -gt 7) { @($cnamesLine[0].Substring(7) -split ',' | Where-Object { $_ }) } else { @() }
    if ($addresses.Count -eq 0) { return [pscustomobject]@{ Status = 'Failure'; Addresses = @(); CnameTargets = $cnameTargets; DurationMilliseconds = $timer.ElapsedMilliseconds; QueryStarted = $queryStarted; Detail = 'Direct DNS probe returned no address text.' } }
    return [pscustomobject]@{ Status = 'Success'; Addresses = $addresses; CnameTargets = $cnameTargets; DurationMilliseconds = $timer.ElapsedMilliseconds; QueryStarted = $queryStarted; Detail = '' }
}

function Test-UsableResolverAddresses([string[]]$Addresses) {
    $groups = Get-UsableResolverAddressGroups $Addresses
    return ($groups.A.Count -gt 0 -or $groups.AAAA.Count -gt 0)
}

function Get-UsableResolverAddressGroups([string[]]$Addresses) {
    $ipv4 = New-Object 'System.Collections.Generic.List[string]'
    $ipv6 = New-Object 'System.Collections.Generic.List[string]'
    foreach ($text in $Addresses) {
        $address = $null
        if (-not [Net.IPAddress]::TryParse($text, [ref]$address)) { continue }
        if ($address.ToString() -in @('0.0.0.0','::')) { continue }
        if ([Net.IPAddress]::IsLoopback($address)) { continue }
        if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { $ipv4.Add($address.IPAddressToString) }
        elseif ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $ipv6.Add($address.IPAddressToString) }
    }
    return [pscustomobject]@{ A = @($ipv4); AAAA = @($ipv6) }
}

function Write-DirectDnsResult([string]$Phase, [string]$Name, [string]$RecordType, $Result) {
    Write-Log ("Direct DNS {0}: {1} {2} => status={3}, answers=[{4}], query-started={5}, elapsed-ms={6} {7}" -f $Phase, $Name, $RecordType, $Result.Status, ($Result.Addresses -join ','), $Result.QueryStarted, $Result.DurationMilliseconds, $Result.Detail)
    if ($Result.CnameTargets.Count -gt 0) { Write-Log ("Direct DNS {0}: {1} CNAME targets=[{2}]" -f $Phase, $Name, ($Result.CnameTargets -join ',')) }
}

function Write-ResolverResult([string]$Phase, [string]$Name, $Result) {
    $addressCount = $Result.Addresses.Count
    $groups = Get-UsableResolverAddressGroups $Result.Addresses
    $addressSummary = if ($Phase -match 'control') { "A=[$($groups.A -join ',')] AAAA=[$($groups.AAAA -join ',')]" } else { "address-count=$addressCount" }
    Write-Log ("Resolver {0}: {1} => status={2}, {3}, query-started={4}, elapsed-ms={5} {6}" -f $Phase, $Name, $Result.Status, $addressSummary, $Result.QueryStarted, $Result.DurationMilliseconds, $Result.Detail)
}

function Invoke-ProductionMode([ValidateSet('Apply','Restore')][string]$Mode) {
    if ($Mode -eq 'Apply') {
        $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode Apply -ListPath "{1}" -BackupPath "{2}"' -f $script:ScriptPath, $script:ListPath, $script:BackupPath
    } else {
        $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode Restore -BackupPath "{1}"' -f $script:ScriptPath, $script:BackupPath
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-BoundedProcess -FileName $script:PowerShellPath -Arguments $arguments -TimeoutSeconds $script:ProcessTimeoutSeconds
    $timer.Stop()
    Write-Log "Production script ${Mode}: exit=$($result.ExitCode), timeout=$($result.TimedOut), elapsed-ms=$($timer.ElapsedMilliseconds)"
    if ($result.StdOut.Trim()) { Write-Log $result.StdOut.Trim() }
    if ($result.StdErr.Trim()) { Write-Log $result.StdErr.Trim() }
    return $result
}

$blockedSample = New-Object 'System.Collections.Generic.List[string]'
$healthyControls = New-Object 'System.Collections.Generic.List[string]'
$originalHash = $null
$originalAttributes = $null
$dnsServer = $null
$runIntegration = $false
$restoreSucceeded = $false

try {
    if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
        throw 'Integration safety guard: run only on a GitHub-hosted Windows runner; this test changes the runner system hosts file.'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Integration precondition failed: the GitHub-hosted Windows runner process is not elevated.'
    }
    if (-not (Test-Path -LiteralPath $script:HostsPath -PathType Leaf)) { throw "Runner hosts file does not exist: $script:HostsPath" }
    if (-not (Test-Path -LiteralPath $script:ListPath -PathType Leaf)) { throw "Bundled block list does not exist: $script:ListPath" }
    if (Test-Path -LiteralPath $script:BackupPath) { Remove-Item -LiteralPath $script:BackupPath -Force }
    [IO.File]::WriteAllText($script:LogPath, '', [Text.Encoding]::UTF8)

    $originalBytes = [IO.File]::ReadAllBytes($script:HostsPath)
    $originalHash = Get-BytesHash $originalBytes
    $originalAttributes = [IO.File]::GetAttributes($script:HostsPath)
    [IO.File]::WriteAllBytes($script:OriginalSnapshotPath, $originalBytes)
    Write-Log "Environment: Windows hosted runner; hosts SHA256=$originalHash; attributes=$originalAttributes"

    Import-Module (Join-Path $PSScriptRoot '..\HostsBlocker.psm1') -Force
    $parsedEntries = @(ConvertTo-BlockEntries ([IO.File]::ReadAllText($script:ListPath)))
    $blockedSet = @{}
    foreach ($entry in $parsedEntries) {
        $parts = $entry -split '\s+', 2
        if ($parts.Count -eq 2) { $blockedSet[$parts[1]] = $true }
    }
    Write-Log "Parsed bundled list entries: $($blockedSet.Count)"

    $controls = @('example.com','github.com','iana.org','www.microsoft.com')
    foreach ($control in $controls) {
        if ($blockedSet.ContainsKey($control)) { throw "Integration test configuration error: control domain '$control' appears in the bundled block list." }
    }

    $flushOk = Invoke-DnsFlush 'baseline'
    if (-not $flushOk) { Add-Failure 'ENVIRONMENT' 'Baseline DNS cache flush failed or timed out; external DNS preflight is inconclusive.' }
    $dnsServer = Get-ConfiguredDnsServer
    if (-not $dnsServer) { Add-Failure 'ENVIRONMENT' 'No configured IPv4 DNS server was found for the baseline network check.' }
    else { Write-Log 'Baseline direct DNS health checks will use the configured IPv4 DNS server (address redacted from artifacts).' }
    Invoke-DnsClientTelemetry -Phase 'baseline'

    foreach ($control in $controls) {
        $resolved = Invoke-OsResolver $control
        Write-ResolverResult -Phase 'baseline control' -Name $control -Result $resolved
        $directA = Invoke-DirectDnsProbe -Name $control -Server $dnsServer -RecordType 'A'
        Write-DirectDnsResult -Phase 'baseline' -Name $control -RecordType 'A' -Result $directA
        $directAAAA = Invoke-DirectDnsProbe -Name $control -Server $dnsServer -RecordType 'AAAA'
        Write-DirectDnsResult -Phase 'baseline' -Name $control -RecordType 'AAAA' -Result $directAAAA
        foreach ($alias in $directA.CnameTargets) {
            if ($blockedSet.ContainsKey($alias)) { throw "Control '$control' has CNAME target '$alias' in the bundled block list; choose an unblocked control record." }
        }
        $osGroups = Get-UsableResolverAddressGroups $resolved.Addresses
        if ($resolved.Status -eq 'Success' -and $osGroups.A.Count -gt 0 -and $directA.Status -eq 'Success' -and (Test-UsableResolverAddresses $directA.Addresses)) {
            $healthyControls.Add($control)
        }
    }
    if ($healthyControls.Count -lt $controls.Count) {
        Add-Failure 'ENVIRONMENT' "External DNS preflight failed: only $($healthyControls.Count) of $($controls.Count) named A-record control cases resolved through both the Windows OS resolver and configured DNS server. The hosts-file test was not run."
    } else {
        Write-Log "External DNS preflight passed for $($healthyControls.Count) control domains."
        $candidateDomains = @(
            'doubleclick.net',
            'ad.doubleclick.net',
            'google-analytics.com',
            'ssl.google-analytics.com',
            'adservice.google.com',
            'googletagmanager.com',
            'www.googletagmanager.com',
            'securepubads.g.doubleclick.net',
            'stats.g.doubleclick.net',
            'pubads.g.doubleclick.net',
            'googleads.g.doubleclick.net',
            'fls.doubleclick.net'
        )
        foreach ($candidate in $candidateDomains) {
            if (-not $blockedSet.ContainsKey($candidate)) {
                Write-Log "Skipping block-list sample '$candidate'; it is not present in this bundled list version."
                continue
            }
            if ($blockedSample.Count -ge 4) { break }
            $resolved = Invoke-OsResolver $candidate
            Write-ResolverResult -Phase 'baseline block-list candidate' -Name $candidate -Result $resolved
            $candidateGroups = Get-UsableResolverAddressGroups $resolved.Addresses
            if ($resolved.Status -eq 'Success' -and $candidateGroups.A.Count -gt 0) {
                $blockedSample.Add($candidate)
            }
        }
        if ($blockedSample.Count -lt 3) {
            Add-Failure 'ENVIRONMENT' "External DNS/filtering preflight failed: only $($blockedSample.Count) bundled block-list sample domains resolved to non-loopback addresses; at least 3 are required. The hosts-file test was not run."
        } elseif ($healthyControls.Count -ge 2 -and $script:EnvironmentFailures.Count -eq 0 -and $script:ScriptFailures.Count -eq 0) {
            $runIntegration = $true
        }
    }

    if ($runIntegration) {
        $apply = Invoke-ProductionMode 'Apply'
        if ($apply.TimedOut -or $apply.ExitCode -ne 0) {
            Add-Failure 'SCRIPT' 'Production Apply failed or timed out on the disposable Windows runner.'
        } else {
            if (-not (Test-Path -LiteralPath $script:BackupPath -PathType Leaf)) {
                Add-Failure 'SCRIPT' 'Production Apply returned success but did not create its requested recovery backup.'
            } else {
                Write-Log 'Production Apply completed and its recovery backup exists.'
                $appliedHostsText = [IO.File]::ReadAllText($script:HostsPath)
                $appliedBlock = [regex]::Match($appliedHostsText, '(?ms)^# BEGIN SOS AD BLOCKER\r?\n(.*?)^# END SOS AD BLOCKER(?:\r?\n|$)')
                if (-not $appliedBlock.Success) {
                    Add-Failure 'SCRIPT' 'Production Apply did not leave a complete managed block in the runner hosts file.'
                } else {
                    $appliedEntries = @(ConvertTo-BlockEntries $appliedBlock.Groups[1].Value)
                    $customNames = @{}
                    $originalText = [Text.Encoding]::UTF8.GetString($originalBytes)
                    foreach ($line in ($originalText -split '\r?\n')) {
                        $parts = (($line -split '#', 2)[0].Trim() -split '\s+')
                        if ($parts.Count -ge 2) {
                            foreach ($name in $parts[1..($parts.Count - 1)]) { $customNames[$name.ToLowerInvariant()] = $true }
                        }
                    }
                    $expectedApplied = @($blockedSet.Keys | Where-Object { -not $customNames.ContainsKey($_) } | Sort-Object)
                    $actualApplied = @($appliedEntries | ForEach-Object { ($_ -split ' ', 2)[1] } | Sort-Object)
                    $mappingLines = @($appliedBlock.Groups[1].Value -split '\r?\n' | Where-Object { $_ })
                    $maxAliases = 0
                    foreach ($mappingLine in $mappingLines) {
                        $aliasCount = (($mappingLine -split '\s+').Count - 1)
                        if ($aliasCount -gt $maxAliases) { $maxAliases = $aliasCount }
                    }
                    Write-Log "Applied block verification: domains=$($actualApplied.Count), lines=$($mappingLines.Count), max-aliases-per-line=$maxAliases"
                    if ($actualApplied.Count -ne $expectedApplied.Count -or ($actualApplied -join "`n") -ne ($expectedApplied -join "`n")) {
                        Add-Failure 'SCRIPT' 'Production Apply changed or omitted domains from the effective full block list.'
                    }
                    if ($maxAliases -gt 9 -or $mappingLines.Count -ge $actualApplied.Count) {
                        Add-Failure 'SCRIPT' 'Production Apply did not use the expected bounded multi-alias line format.'
                    }
                }
            }

            if (-not (Invoke-DnsFlush 'after Apply')) { Add-Failure 'ENVIRONMENT' 'DNS cache flush after Apply failed or timed out.' }
            Invoke-DnsClientTelemetry -Phase 'after Apply'
            $blockedResolverFailures = New-Object 'System.Collections.Generic.List[string]'
            foreach ($domain in $blockedSample) {
                $resolved = Invoke-OsResolver $domain
                Write-ResolverResult -Phase 'after Apply blocked-domain assertion' -Name $domain -Result $resolved
                if ($resolved.Status -ne 'Success') {
                    $blockedResolverFailures.Add($domain)
                } elseif (@($resolved.Addresses | Where-Object { $_ -ne '0.0.0.0' }).Count -gt 0) {
                    Add-Failure 'SCRIPT' "Apply returned non-blocked addresses for '$domain' (address-count=$($resolved.Addresses.Count))."
                } else {
                    Write-Log "PASS: Windows OS resolver returned only the configured 0.0.0.0 block mapping for '$domain'."
                }
            }
            $controlResolverFailures = New-Object 'System.Collections.Generic.List[string]'
            foreach ($control in $healthyControls) {
                $resolved = Invoke-OsResolver $control
                Write-ResolverResult -Phase 'after Apply control assertion' -Name $control -Result $resolved
                $osGroups = Get-UsableResolverAddressGroups $resolved.Addresses
                if ($resolved.Status -ne 'Success' -or $osGroups.A.Count -eq 0) {
                    $controlResolverFailures.Add($control)
                } elseif (@($resolved.Addresses | Where-Object { $_ -eq '0.0.0.0' }).Count -gt 0) {
                    Add-Failure 'SCRIPT' "Apply unexpectedly blocked control domain '$control'."
                }
            }
            Invoke-DnsClientTelemetry -Phase 'after Apply resolver probes'
            foreach ($domain in $blockedResolverFailures) {
                $direct = Invoke-DirectDnsProbe -Name $domain -Server $dnsServer
                Write-DirectDnsResult -Phase 'after Apply' -Name $domain -RecordType 'A' -Result $direct
                if ($direct.Status -eq 'Success' -and (Test-UsableResolverAddresses $direct.Addresses)) {
                    Write-Log "PASS: Windows OS resolver did not return an address for blocked '$domain'; direct DNS remains healthy and the verified hosts mapping takes precedence."
                } else {
                    Add-Failure 'ENVIRONMENT' "Neither the Windows OS resolver nor the configured DNS server resolved '$domain' after Apply."
                }
            }
            foreach ($control in $controlResolverFailures) {
                $direct = Invoke-DirectDnsProbe -Name $control -Server $dnsServer
                Write-DirectDnsResult -Phase 'after Apply' -Name $control -RecordType 'A' -Result $direct
                if ($direct.Status -eq 'Success' -and (Test-UsableResolverAddresses $direct.Addresses)) {
                    Add-Failure 'SCRIPT' "The configured DNS server still resolves control '$control', but the Windows OS resolver failed after Apply."
                } else {
                    Add-Failure 'ENVIRONMENT' "External DNS/network health check for control '$control' failed after Apply."
                }
            }
        }
    }
} catch {
    Add-Failure 'SCRIPT' $_.Exception.Message
} finally {
    if ($originalHash) {
        $backupExists = Test-Path -LiteralPath $script:BackupPath -PathType Leaf
        $state = Get-HostsFileState
        if ($backupExists) {
            try {
                $restore = Invoke-ProductionMode 'Restore'
                if ($restore.TimedOut -or $restore.ExitCode -ne 0) {
                    Add-Failure 'SCRIPT' 'Production Restore failed or timed out during cleanup; attempting emergency cleanup on the disposable runner.'
                } else {
                    Write-Log 'Production Restore returned success during cleanup.'
                }
            } catch {
                Add-Failure 'SCRIPT' "Production Restore could not start or complete during cleanup: $($_.Exception.Message)"
            }
        } elseif (-not $state.Readable -or $state.Hash -ne $originalHash -or $state.Attributes -ne $originalAttributes) {
            Add-Failure 'SCRIPT' 'The runner hosts file changed but the production recovery backup is missing; using the private original snapshot for runner-only cleanup.'
        }

        $state = Get-HostsFileState
        if (-not $state.Readable -or $state.Hash -ne $originalHash -or $state.Attributes -ne $originalAttributes) {
            if (-not $state.Readable) { Add-Failure 'SCRIPT' "Could not inspect hosts file before emergency cleanup: $($state.Error)" }
            try {
                $emergencyArguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -EmergencyRestore' -f $script:HarnessPath
                $emergency = Invoke-BoundedProcess -FileName $script:PowerShellPath -Arguments $emergencyArguments -TimeoutSeconds $script:ProcessTimeoutSeconds -Environment @{
                    SOS_DNS_E2E_ORIGINAL_SNAPSHOT = $script:OriginalSnapshotPath
                    SOS_DNS_E2E_ORIGINAL_HASH = $originalHash
                    SOS_DNS_E2E_ORIGINAL_ATTRIBUTES = [string][int]$originalAttributes
                }
                Write-Log "Emergency runner-only restore: exit=$($emergency.ExitCode), timeout=$($emergency.TimedOut)"
                if ($emergency.StdErr.Trim()) { Write-Log $emergency.StdErr.Trim() }
                if ($emergency.TimedOut -or $emergency.ExitCode -ne 0) {
                    Add-Failure 'SCRIPT' 'Emergency cleanup could not restore the disposable runner hosts file from its original snapshot.'
                }
            } catch {
                Add-Failure 'SCRIPT' "Emergency cleanup could not start: $($_.Exception.Message)"
            }
        }

        $state = Get-HostsFileState
        if (-not $state.Readable) {
            Add-Failure 'SCRIPT' "Final hosts-file integrity check could not read the file: $($state.Error)"
        } elseif ($state.Hash -ne $originalHash) {
            Add-Failure 'SCRIPT' "Final hosts-file integrity check failed: expected $originalHash, got $($state.Hash)."
        } elseif ($state.Attributes -ne $originalAttributes) {
            Add-Failure 'SCRIPT' "Final hosts-file attribute check failed: expected '$originalAttributes', got '$($state.Attributes)'."
        } else {
            Write-Log 'Verified exact original hosts bytes and file attributes after cleanup.'
            $restoreSucceeded = $true
        }
        try {
            if (Test-Path -LiteralPath $script:BackupPath) {
                Add-Failure 'SCRIPT' 'Recovery backup remains after cleanup; expected the verified restore to remove it.'
            }
        } catch { Add-Failure 'SCRIPT' "Could not verify recovery backup cleanup: $($_.Exception.Message)" }
        if ($restoreSucceeded -and (Test-Path -LiteralPath $script:OriginalSnapshotPath)) {
            try { Remove-Item -LiteralPath $script:OriginalSnapshotPath -Force }
            catch { Add-Failure 'SCRIPT' "Could not remove verified private snapshot: $($_.Exception.Message)" }
        }

        if ($restoreSucceeded -and $blockedSample.Count -gt 0 -and $healthyControls.Count -ge 2) {
            if (-not (Invoke-DnsFlush 'after Restore')) { Add-Failure 'ENVIRONMENT' 'DNS cache flush after Restore failed or timed out.' }
            foreach ($control in $healthyControls) {
                $resolved = Invoke-OsResolver $control
                Write-ResolverResult -Phase 'after Restore control assertion' -Name $control -Result $resolved
                $osGroups = Get-UsableResolverAddressGroups $resolved.Addresses
                if ($resolved.Status -ne 'Success' -or $osGroups.A.Count -eq 0) {
                    $direct = Invoke-DirectDnsProbe -Name $control -Server $dnsServer -RecordType 'A'
                    Write-DirectDnsResult -Phase 'after Restore' -Name $control -RecordType 'A' -Result $direct
                    if ($direct.Status -eq 'Success' -and (Test-UsableResolverAddresses $direct.Addresses)) {
                        Add-Failure 'SCRIPT' "The configured DNS server still resolves control '$control', but the Windows OS resolver failed after Restore."
                    } else {
                        Add-Failure 'ENVIRONMENT' "External DNS/network health check for control '$control' failed after Restore."
                    }
                } elseif (@($resolved.Addresses | Where-Object { $_ -eq '0.0.0.0' }).Count -gt 0) {
                    $direct = Invoke-DirectDnsProbe -Name $control -Server $dnsServer -RecordType 'A'
                    Write-DirectDnsResult -Phase 'after Restore' -Name $control -RecordType 'A' -Result $direct
                    if ($direct.Status -eq 'Success' -and (Test-UsableResolverAddresses $direct.Addresses)) {
                        Add-Failure 'SCRIPT' "Control domain '$control' remained blocked in the Windows OS resolver after Restore."
                    } else {
                        Add-Failure 'ENVIRONMENT' "Control '$control' no longer resolves externally after Restore."
                    }
                }
            }
            foreach ($domain in $blockedSample) {
                $resolved = Invoke-OsResolver $domain
                Write-ResolverResult -Phase 'after Restore previously-blocked assertion' -Name $domain -Result $resolved
                $osGroups = Get-UsableResolverAddressGroups $resolved.Addresses
                if ($resolved.Status -ne 'Success' -or $osGroups.A.Count -eq 0) {
                    $direct = Invoke-DirectDnsProbe -Name $domain -Server $dnsServer -RecordType 'A'
                    Write-DirectDnsResult -Phase 'after Restore' -Name $domain -RecordType 'A' -Result $direct
                    if ($direct.Status -eq 'Success' -and (Test-UsableResolverAddresses $direct.Addresses)) {
                        Add-Failure 'SCRIPT' "The configured DNS server still resolves '$domain', but the Windows OS resolver failed after Restore."
                    } else {
                        Add-Failure 'ENVIRONMENT' "Previously resolvable domain '$domain' is no longer available from external DNS after Restore."
                    }
                } elseif (@($resolved.Addresses | Where-Object { $_ -eq '0.0.0.0' }).Count -gt 0) {
                    $direct = Invoke-DirectDnsProbe -Name $domain -Server $dnsServer -RecordType 'A'
                    Write-DirectDnsResult -Phase 'after Restore' -Name $domain -RecordType 'A' -Result $direct
                    if ($direct.Status -eq 'Success' -and (Test-UsableResolverAddresses $direct.Addresses)) {
                        Add-Failure 'SCRIPT' "Previously blocked domain '$domain' still resolves to 0.0.0.0 in the Windows OS resolver after verified Restore and cache flush."
                    } else {
                        Add-Failure 'ENVIRONMENT' "Previously blocked domain '$domain' stopped resolving externally during the test."
                    }
                } else {
                    Write-Log "PASS: previously blocked domain '$domain' resolved again after Restore."
                }
            }
        }
    }

    $overall = if ($script:ScriptFailures.Count -gt 0) { 'SCRIPT_REGRESSION' } elseif ($script:EnvironmentFailures.Count -gt 0) { 'ENVIRONMENT_FAILURE' } else { 'PASS' }
    Write-Log "Final result: $overall"
    $summary = @(
        '# Windows DNS integration test',
        '',
        "Result: **$overall**",
        "Windows runner: GitHub-hosted disposable VM (`$env:ImageOS`)",
        "Bundled domains tested: $($blockedSample -join ', ')",
        "Control domains tested: $($healthyControls -join ', ')",
        "Original hosts SHA256: $originalHash",
        "Exact hosts bytes and attributes restored: $restoreSucceeded"
    )
    if ($script:EnvironmentFailures.Count -gt 0) { $summary += @('', '## Environment limitations', ($script:EnvironmentFailures | ForEach-Object { "- $_" })) }
    if ($script:ScriptFailures.Count -gt 0) { $summary += @('', '## Script or harness failures', ($script:ScriptFailures | ForEach-Object { "- $_" })) }
    [IO.File]::WriteAllLines($script:SummaryPath, [string[]]$summary, [Text.Encoding]::UTF8)
}

if ($script:ScriptFailures.Count -gt 0) { exit 1 }
if ($script:EnvironmentFailures.Count -gt 0) { exit 2 }
exit 0
