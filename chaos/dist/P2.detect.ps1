# STT - Chaos - P2 Credential Guard running
# Configuration check: this machine (Pass-the-hash). Proves: Login secrets are isolated from Windows itself.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/P2.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

$script:ChaosId = 'P2'
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction SilentlyContinue
    if ($null -eq $dg) { Write-Verdict -Verdict 'FAIL' -Summary 'Device Guard information is not available, so Credential Guard is not running.' }
    Add-Detail "SecurityServicesConfigured = $(@($dg.SecurityServicesConfigured) -join ','); SecurityServicesRunning = $(@($dg.SecurityServicesRunning) -join ',')"
    if (@($dg.SecurityServicesRunning) -contains 1) { Write-Verdict -Verdict 'PASS' -Summary 'Credential Guard is running.' }
    Write-Verdict -Verdict 'FAIL' -Summary "Credential Guard is not running$(if (@($dg.SecurityServicesConfigured) -contains 1) { ' (configured, but not running)' })."
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
