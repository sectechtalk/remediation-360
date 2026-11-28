# STT - Chaos - P1 LAPS manages the local admin password
# Configuration check: this machine (Pass-the-hash). Proves: Every machine has a unique, rotating local admin password.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/P1.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

#region Base
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$script:Detail = New-Object -TypeName System.Collections.Generic.List[string]

# One line of detail under the verdict.
function Add-Detail {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $script:Detail.Add($Text)
}

# Prints the verdict and the details (Intune keeps about 2,000 characters) and ends the script. Only PASS exits 0, so
# FAIL and COULD NOT TEST never show a machine as hardened.
function Write-Verdict {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'FAIL', 'COULD NOT TEST')][string]$Verdict,
        [Parameter(Mandatory = $true)][string]$Summary
    )
    $text = (@("$Verdict ${script:ChaosId}: $Summary") + @($script:Detail)) -join "`n"
    if ($text.Length -gt 2000) { $text = $text.Substring(0, 1980) + "`n... (cut)" }
    Write-Output $text
    if ($Verdict -eq 'PASS') { exit 0 }
    exit 1
}

# Probes and AD checks need a machine joined to an AD domain.
function Test-DomainJoined {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    return [bool]$cs.PartOfDomain
}
#endregion

#region Laps
# The Windows LAPS policy in force: the first policy root that has any value (CSP, then Group Policy, then local
# config, then legacy Microsoft LAPS), as Windows LAPS itself picks it. $null when no root has a value.
function Get-LapsPolicy {
    $roots = @(
        @{ Name = 'Intune (CSP)'; Path = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' },
        @{ Name = 'Group Policy'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' },
        @{ Name = 'Local configuration'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' },
        @{ Name = 'Legacy Microsoft LAPS'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' }
    )
    foreach ($root in $roots) {
        $item = Get-ItemProperty -Path $root.Path -ErrorAction SilentlyContinue
        if ($null -eq $item) { continue }
        $values = @{}
        foreach ($p in $item.PSObject.Properties) { if ($p.Name -notlike 'PS*') { $values[$p.Name] = $p.Value } }
        if ($values.Count -eq 0) { continue }
        return [pscustomobject]@{ Source = $root.Name; Legacy = ($root.Name -like 'Legacy*'); Values = $values }
    }
    return $null
}

# A LAPS setting from the policy, or its Windows default when the policy leaves it out.
function Get-LapsSetting {
    param([Parameter(Mandatory = $true)]$Policy, [Parameter(Mandatory = $true)][string]$Name, $Default)
    if ($Policy.Values.ContainsKey($Name)) { return $Policy.Values[$Name] }
    return $Default
}
#endregion

#region Event
# Events from a log since a date, or an empty list when there are none (Get-WinEvent throws on no match).
function Get-RecentEvent {
    param([Parameter(Mandatory = $true)][string]$LogName, [Parameter(Mandatory = $true)][int[]]$Id, [Parameter(Mandatory = $true)][DateTime]$Since, [int]$MaxEvents = 500)
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Id; StartTime = $Since } -MaxEvents $MaxEvents -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound|NoMatchingLogsFound') { return @() }
        throw
    }
}
#endregion

$script:ChaosId = 'P1'
try {
    $p = Get-LapsPolicy
    if ($null -eq $p) { Write-Verdict -Verdict 'FAIL' -Summary 'no LAPS policy reaches this machine.' }
    if ($p.Legacy) { $dir = if ((Get-LapsSetting -Policy $p -Name 'AdmPwdEnabled' -Default 0) -eq 1) { 2 } else { 0 } } else { $dir = [int](Get-LapsSetting -Policy $p -Name 'BackupDirectory' -Default 0) }
    $age = [int](Get-LapsSetting -Policy $p -Name 'PasswordAgeDays' -Default 30)
    Add-Detail "Policy from $($p.Source); backup to $(@('nowhere (disabled)', 'Entra ID', 'Active Directory')[[Math]::Min($dir, 2)]); password age $age days"
    if ($dir -notin 1, 2) { Write-Verdict -Verdict 'FAIL' -Summary 'LAPS does not back up the password (BackupDirectory is 0).' }
    $window = [Math]::Max(30, $age + 1)
    $events = Get-RecentEvent -LogName 'Microsoft-Windows-LAPS/Operational' -Id 10018, 10029 -Since (Get-Date).AddDays(-$window) -MaxEvents 1
    if ($events.Count -eq 0) { Write-Verdict -Verdict 'FAIL' -Summary "no successful LAPS password backup (event 10018 or 10029) in the last $window days." }
    Write-Verdict -Verdict 'PASS' -Summary "LAPS rotated and backed up the password on $($events[0].TimeCreated.ToString('yyyy-MM-dd'))."
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
