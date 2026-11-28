# STT - Chaos - C2 WebClient off
# Configuration check: this machine (LDAP and coercion). Proves: This machine cannot be coerced into NTLM over HTTP (WebDAV).
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/C2.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

$script:ChaosId = 'C2'
try {
    $svc = Get-Service -Name 'WebClient' -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Write-Verdict -Verdict 'PASS' -Summary 'the WebClient service is not installed.' }
    Add-Detail "WebClient: start type $($svc.StartType), $($svc.Status)"
    if ($svc.StartType -eq 'Disabled') { Write-Verdict -Verdict 'PASS' -Summary 'the WebClient service is disabled.' }
    Write-Verdict -Verdict 'FAIL' -Summary "the WebClient service is $($svc.StartType) and $($svc.Status)."
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
