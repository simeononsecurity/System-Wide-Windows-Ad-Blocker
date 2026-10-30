#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ResolveName,
    [switch]$DnsProbe,
    [switch]$EmergencyRestore
)

$ErrorActionPreference = 'Stop'

# The resolver child is deliberately a separate Windows PowerShell process so
# the parent can enforce a hard timeout around the OS hostname-resolution API.
if ($ResolveName) {
    $name = $env:SOS_DNS_E2E_RESOLVE_NAME
    if ($name -notmatch '^(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$') {
        [Console]::Error.WriteLine('Resolver received an invalid DNS name.')
        exit 64
    }
    try {
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
    if ($name -notmatch '^(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$' -or -not $server) {
        [Console]::Error.WriteLine('DNS health probe received an invalid name or server.')
        exit 64
    }
    try {
        $addresses = @(Resolve-DnsName -Name $name -Server $server -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'A' -and $_.IPAddress } | ForEach-Object { $_.IPAddress } | Sort-Object -Unique)
        if ($addresses.Count -eq 0) {
            [Console]::Error.WriteLine('The configured DNS server returned no A records.')
            exit 2
        }
        [Console]::Out.WriteLine(($addresses -join ','))
        exit 0
    } catch {
        [Console]::Error.WriteLine('Direct DNS health query failed.')
        exit 2
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
$script:Applied = $false
$script:HostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$script:BackupPath = Join-Path $env:RUNNER_TEMP 'dns-integration-backup.json'
$script:OriginalSnapshotPath = Join-Path $env:RUNNER_TEMP 'dns-integration-original-hosts.bin'
$script:PowerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:ScriptPath = Join-Path $PSScriptRoot '..\sos-system-wide-windows-ad-block.ps1'
$script:ListPath = Join-Path $PSScriptRoot '..\Files\hosts.txt'
$script:ResolverTimeoutSeconds = 6
$script:ProcessTimeoutSeconds = 120
$script:FlushTimeoutSeconds = 15

function Write-Log([string]$Message) {
    $line = '[{0}] {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"), $Message
    Write-Host $line
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
    $ipconfig = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
    $result = Invoke-BoundedProcess -FileName $ipconfig -Arguments '/flushdns' -TimeoutSeconds $script:FlushTimeoutSeconds
    Write-Log "DNS cache flush ($Phase): exit=$($result.ExitCode), timeout=$($result.TimedOut)"
    if ($result.StdOut.Trim()) { Write-Log $result.StdOut.Trim() }
    if ($result.StdErr.Trim()) { Write-Log $result.StdErr.Trim() }
    return (-not $result.TimedOut -and $result.ExitCode -eq 0)
}

function Invoke-OsResolver([string]$Name) {
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -ResolveName' -f $script:ScriptPath
    $result = Invoke-BoundedProcess -FileName $script:PowerShellPath -Arguments $arguments -TimeoutSeconds $script:ResolverTimeoutSeconds -Environment @{ SOS_DNS_E2E_RESOLVE_NAME = $Name }
    if ($result.TimedOut) {
        return [pscustomobject]@{ Status = 'Timeout'; Addresses = @(); Detail = 'OS resolver exceeded the timeout.' }
    }
    if ($result.ExitCode -ne 0) {
        return [pscustomobject]@{ Status = 'Failure'; Addresses = @(); Detail = $result.StdErr.Trim() }
    }
    $addresses = @($result.StdOut.Trim() -split ',' | Where-Object { $_ })
    if ($addresses.Count -eq 0) { return [pscustomobject]@{ Status = 'Failure'; Addresses = @(); Detail = 'OS resolver returned no address text.' } }
    return [pscustomobject]@{ Status = 'Success'; Addresses = $addresses; Detail = '' }
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

function Invoke-DirectDnsProbe([string]$Name, [string]$Server) {
    if (-not $Server) { return [pscustomobject]@{ Status = 'Unavailable'; Addresses = @(); Detail = 'No configured IPv4 DNS server was found.' } }
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -DnsProbe' -f $script:ScriptPath
    $result = Invoke-BoundedProcess -FileName $script:PowerShellPath -Arguments $arguments -TimeoutSeconds $script:ResolverTimeoutSeconds -Environment @{
        SOS_DNS_E2E_RESOLVE_NAME = $Name
        SOS_DNS_E2E_DNS_SERVER = $Server
    }
    if ($result.TimedOut) { return [pscustomobject]@{ Status = 'Timeout'; Addresses = @(); Detail = 'Direct DNS health probe exceeded the timeout.' } }
    if ($result.ExitCode -ne 0) { return [pscustomobject]@{ Status = 'Failure'; Addresses = @(); Detail = $result.StdErr.Trim() } }
    $addresses = @($result.StdOut.Trim() -split ',' | Where-Object { $_ })
    if ($addresses.Count -eq 0) { return [pscustomobject]@{ Status = 'Failure'; Addresses = @(); Detail = 'Direct DNS probe returned no address text.' } }
    return [pscustomobject]@{ Status = 'Success'; Addresses = $addresses; Detail = '' }
}

function Test-UsableResolverAddresses([string[]]$Addresses) {
    foreach ($text in $Addresses) {
        $address = $null
        if (-not [Net.IPAddress]::TryParse($text, [ref]$address)) { continue }
        if ($address.ToString() -in @('0.0.0.0','::')) { continue }
        if ([Net.IPAddress]::IsLoopback($address)) { continue }
        return $true
    }
    return $false
}

function Write-ResolverResult([string]$Phase, [string]$Name, $Result) {
    $addressCount = $Result.Addresses.Count
    Write-Log ("Resolver {0}: {1} => status={2}, address-count={3} {4}" -f $Phase, $Name, $Result.Status, $addressCount, $Result.Detail)
}

function Invoke-ProductionMode([ValidateSet('Apply','Restore')][string]$Mode) {
    if ($Mode -eq 'Apply') {
        $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode Apply -ListPath "{1}" -BackupPath "{2}" -Confirm:$false' -f $script:ScriptPath, $script:ListPath, $script:BackupPath
    } else {
        $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode Restore -BackupPath "{1}" -Confirm:$false' -f $script:ScriptPath, $script:BackupPath
    }
    $result = Invoke-BoundedProcess -FileName $script:PowerShellPath -Arguments $arguments -TimeoutSeconds $script:ProcessTimeoutSeconds
    Write-Log "Production script ${Mode}: exit=$($result.ExitCode), timeout=$($result.TimedOut)"
    if ($result.StdOut.Trim()) { Write-Log $result.StdOut.Trim() }
    if ($result.StdErr.Trim()) { Write-Log $result.StdErr.Trim() }
    return $result
}

$blockedBaseline = @{}
$controlsBaseline = @{}
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

    $controls = @('example.com','github.com','www.microsoft.com')
    foreach ($control in $controls) {
        if ($blockedSet.ContainsKey($control)) { throw "Integration test configuration error: control domain '$control' appears in the bundled block list." }
    }

    $flushOk = Invoke-DnsFlush 'baseline'
    if (-not $flushOk) { Add-Failure 'ENVIRONMENT' 'Baseline DNS cache flush failed or timed out; external DNS preflight is inconclusive.' }
    $dnsServer = Get-ConfiguredDnsServer
    if (-not $dnsServer) { Add-Failure 'ENVIRONMENT' 'No configured IPv4 DNS server was found for the baseline network check.' }
    else { Write-Log 'Baseline direct DNS health checks will use the configured IPv4 DNS server (address redacted from artifacts).' }

    foreach ($control in $controls) {
        $resolved = Invoke-OsResolver $control
        Write-ResolverResult 'baseline control' $control $resolved
        $direct = Invoke-DirectDnsProbe $control $dnsServer
        Write-Log ("Direct DNS baseline: {0} via configured server => status={1}, address-count={2}" -f $control, $direct.Status, $direct.Addresses.Count)
        if ($resolved.Status -eq 'Success' -and (Test-UsableResolverAddresses $resolved.Addresses) -and $direct.Status -eq 'Success' -and (Test-UsableResolverAddresses $direct.Addresses)) {
            $controlsBaseline[$control] = $resolved.Addresses
            $healthyControls.Add($control)
        }
    }
    if ($healthyControls.Count -lt 2) {
        Add-Failure 'ENVIRONMENT' "External DNS preflight failed: only $($healthyControls.Count) of 3 baseline controls resolved. The hosts-file test was not run."
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
            Write-ResolverResult 'baseline block-list candidate' $candidate $resolved
            if ($resolved.Status -eq 'Success' -and (Test-UsableResolverAddresses $resolved.Addresses)) {
                $blockedBaseline[$candidate] = $resolved.Addresses
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
            $script:Applied = $true
            if (-not (Test-Path -LiteralPath $script:BackupPath -PathType Leaf)) {
                Add-Failure 'SCRIPT' 'Production Apply returned success but did not create its requested recovery backup.'
            } else {
                Write-Log 'Production Apply completed and its recovery backup exists.'
            }

            if (-not (Invoke-DnsFlush 'after Apply')) { Add-Failure 'ENVIRONMENT' 'DNS cache flush after Apply failed or timed out.' }
            $blockedResolverFailures = New-Object 'System.Collections.Generic.List[string]'
            foreach ($domain in $blockedSample) {
                $resolved = Invoke-OsResolver $domain
                Write-ResolverResult 'after Apply blocked-domain assertion' $domain $resolved
                if ($resolved.Status -ne 'Success') {
                    $blockedResolverFailures.Add($domain)
                } elseif (@($resolved.Addresses | Where-Object { $_ -eq '0.0.0.0' }).Count -eq 0) {
                    Add-Failure 'SCRIPT' "Apply did not block '$domain' through the Windows OS resolver."
                } elseif (@($resolved.Addresses | Where-Object { $_ -ne '0.0.0.0' }).Count -gt 0) {
                    Add-Failure 'SCRIPT' "Apply returned non-blocked addresses for '$domain' (address-count=$($resolved.Addresses.Count))."
                }
            }
            $controlResolverFailures = New-Object 'System.Collections.Generic.List[string]'
            foreach ($control in $healthyControls) {
                $resolved = Invoke-OsResolver $control
                Write-ResolverResult 'after Apply control assertion' $control $resolved
                if ($resolved.Status -ne 'Success' -or -not (Test-UsableResolverAddresses $resolved.Addresses)) {
                    $controlResolverFailures.Add($control)
                } elseif (@($resolved.Addresses | Where-Object { $_ -eq '0.0.0.0' }).Count -gt 0) {
                    Add-Failure 'SCRIPT' "Apply unexpectedly blocked control domain '$control'."
                }
            }
            foreach ($domain in $blockedResolverFailures) {
                $direct = Invoke-DirectDnsProbe $domain $dnsServer
                Write-Log ("Direct DNS after Apply: {0} via configured server => status={1}, address-count={2}" -f $domain, $direct.Status, $direct.Addresses.Count)
                if ($direct.Status -eq 'Success' -and (Test-UsableResolverAddresses $direct.Addresses)) {
                    Add-Failure 'SCRIPT' "The configured DNS server still resolves '$domain', but the Windows OS resolver failed after Apply."
                } else {
                    Add-Failure 'ENVIRONMENT' "Neither the Windows OS resolver nor the configured DNS server resolved '$domain' after Apply."
                }
            }
            foreach ($control in $controlResolverFailures) {
                $direct = Invoke-DirectDnsProbe $control $dnsServer
                Write-Log ("Direct DNS after Apply: {0} via configured server => status={1}, address-count={2}" -f $control, $direct.Status, $direct.Addresses.Count)
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
                $emergencyArguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -EmergencyRestore' -f $script:ScriptPath
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
                Write-ResolverResult 'after Restore control assertion' $control $resolved
                if ($resolved.Status -ne 'Success' -or -not (Test-UsableResolverAddresses $resolved.Addresses)) {
                    $direct = Invoke-DirectDnsProbe $control $dnsServer
                    Write-Log ("Direct DNS after Restore: {0} via configured server => status={1}, address-count={2}" -f $control, $direct.Status, $direct.Addresses.Count)
                    if ($direct.Status -eq 'Success' -and (Test-UsableResolverAddresses $direct.Addresses)) {
                        Add-Failure 'SCRIPT' "The configured DNS server still resolves control '$control', but the Windows OS resolver failed after Restore."
                    } else {
                        Add-Failure 'ENVIRONMENT' "External DNS/network health check for control '$control' failed after Restore."
                    }
                } elseif (@($resolved.Addresses | Where-Object { $_ -eq '0.0.0.0' }).Count -gt 0) {
                    $direct = Invoke-DirectDnsProbe $control $dnsServer
                    Write-Log ("Direct DNS after Restore: {0} via configured server => status={1}, address-count={2}" -f $control, $direct.Status, $direct.Addresses.Count)
                    if ($direct.Status -eq 'Success' -and (Test-UsableResolverAddresses $direct.Addresses)) {
                        Add-Failure 'SCRIPT' "Control domain '$control' remained blocked in the Windows OS resolver after Restore."
                    } else {
                        Add-Failure 'ENVIRONMENT' "Control '$control' no longer resolves externally after Restore."
                    }
                }
            }
            foreach ($domain in $blockedSample) {
                $resolved = Invoke-OsResolver $domain
                Write-ResolverResult 'after Restore previously-blocked assertion' $domain $resolved
                if ($resolved.Status -ne 'Success') {
                    $direct = Invoke-DirectDnsProbe $domain $dnsServer
                    Write-Log ("Direct DNS after Restore: {0} via configured server => status={1}, address-count={2}" -f $domain, $direct.Status, $direct.Addresses.Count)
                    if ($direct.Status -eq 'Success' -and (Test-UsableResolverAddresses $direct.Addresses)) {
                        Add-Failure 'SCRIPT' "The configured DNS server still resolves '$domain', but the Windows OS resolver failed after Restore."
                    } else {
                        Add-Failure 'ENVIRONMENT' "Previously resolvable domain '$domain' is no longer available from external DNS after Restore."
                    }
                } elseif (@($resolved.Addresses | Where-Object { $_ -eq '0.0.0.0' }).Count -gt 0) {
                    $direct = Invoke-DirectDnsProbe $domain $dnsServer
                    Write-Log ("Direct DNS after Restore: {0} via configured server => status={1}, address-count={2}" -f $domain, $direct.Status, $direct.Addresses.Count)
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
