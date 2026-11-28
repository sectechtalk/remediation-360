# STT - Chaos - N5 No NTLM leaves this machine
# Configuration check: this machine (NTLM). Proves: Reduction stage 2: this machine uses Kerberos only.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/N5.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

#region Reg
# A registry value, or $null when the key or value is missing.
function Get-RegValue {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Name)
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
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

$script:ChaosId = 'N5'
try {
    $send = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic'
    Add-Detail "RestrictSendingNTLMTraffic = $(if ($null -eq $send) { 'not set' } else { $send })"
    if ($send -eq 2) { Write-Verdict -Verdict 'PASS' -Summary 'outgoing NTLM is blocked (RestrictSendingNTLMTraffic = 2).' }
    if ($send -ne 1) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'outgoing NTLM is not audited (N4), so NTLM use is not logged here.' }
    $events = Get-RecentEvent -LogName 'Microsoft-Windows-NTLM/Operational' -Id 8001 -Since (Get-Date).AddDays(-7) -MaxEvents 2000
    if ($events.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no outgoing NTLM in the last 7 days (NTLM event 8001).' }
    $servers = @($events | ForEach-Object { [string]$_.Properties[0].Value } | Where-Object { $_ } | Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 15 | ForEach-Object { "$($_.Name) ($($_.Count))" })
    Add-Detail "Servers it used NTLM with: $($servers -join ', ')"
    Write-Verdict -Verdict 'FAIL' -Summary "$($events.Count) outgoing NTLM login(s) in the last 7 days."
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
