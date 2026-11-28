# STT - Chaos - P3 LSA protection on
# Configuration check: this machine (Pass-the-hash). Proves: Tools cannot read the memory of the login process.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/P3.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

$script:ChaosId = 'P3'
try {
    $ppl = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'
    $pplBoot = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPLBoot'
    Add-Detail "RunAsPPL = $(if ($null -eq $ppl) { 'not set' } else { $ppl }); RunAsPPLBoot = $(if ($null -eq $pplBoot) { 'not set' } else { $pplBoot })"
    $boot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $started = $false
    try {
        $started = [bool](Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Wininit'; Id = 12; StartTime = $boot } -MaxEvents 1 -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw }
    }
    Add-Detail "Wininit event 12 (LSASS started as a protected process) since boot: $(if ($started) { 'yes' } else { 'no' })"
    if ($ppl -in 1, 2 -or $pplBoot -in 1, 2 -or $started) { Write-Verdict -Verdict 'PASS' -Summary 'LSA protection is on.' }
    Write-Verdict -Verdict 'FAIL' -Summary 'LSA protection is off (RunAsPPL is not 1 or 2).'
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
