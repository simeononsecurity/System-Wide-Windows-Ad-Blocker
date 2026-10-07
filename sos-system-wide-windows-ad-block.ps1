#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Apply','Restore')][string]$Mode = 'Apply',
    [string]$BackupPath = (Join-Path $env:ProgramData 'SoS-Hosts\backup.json'),
    [string]$ListPath,
    [uri]$ListUri = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
)
$ErrorActionPreference = 'Stop'
try {
    Import-Module (Join-Path $PSScriptRoot 'HostsBlocker.psm1') -Force
    $confirmation = @{}
    if ($PSBoundParameters.ContainsKey('Confirm')) { $confirmation['Confirm'] = $PSBoundParameters['Confirm'] }
    Invoke-HostsBlocker -HostsPath (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -BackupPath $BackupPath -Mode $Mode -ListPath $ListPath -ListUri $ListUri -WhatIf:$WhatIfPreference @confirmation
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
