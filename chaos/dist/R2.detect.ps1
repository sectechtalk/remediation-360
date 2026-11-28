# STT - Chaos - R2 NBT-NS off
# Configuration check: this machine (Name resolution). Proves: NetBIOS name lookups are off on every network adapter.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/R2.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

$script:ChaosId = 'R2'
try {
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    $adapters = @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'Tcpip_*' })
    if ($adapters.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'NetBIOS over TCP/IP is not bound to any adapter.' }
    $on = @()
    foreach ($a in $adapters) {
        $v = Get-RegValue -Path $a.PSPath -Name 'NetbiosOptions'
        if ($v -ne 2) { $on += "$($a.PSChildName -replace '^Tcpip_', '') = $(if ($null -eq $v) { 'not set' } else { $v })" }
    }
    if ($on.Count -gt 0) { $on | Select-Object -First 15 | ForEach-Object { Add-Detail $_ }; Write-Verdict -Verdict 'FAIL' -Summary "NetBIOS is not off on $($on.Count) of $($adapters.Count) adapters (0 = from DHCP, 1 = on)." }
    Write-Verdict -Verdict 'PASS' -Summary "NetBIOS is off on all $($adapters.Count) adapters."
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
