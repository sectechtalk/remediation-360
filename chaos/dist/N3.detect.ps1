# STT - Chaos - N3 DCs refuse NTLMv1
# Active probe (NTLM). Proves: Every domain controller rejects an NTLMv1 login.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/N3.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

$script:ChaosId = 'N3'
try {
    # An NTLMv1 login needs a login client that still speaks NTLMv1 and a test account to log in with. Windows 11 24H2
    # and Server 2025 removed NTLMv1, so Windows itself cannot make the attempt. Until that client is built this test
    # reports COULD NOT TEST, never PASS.
    Add-Detail 'Windows on this machine cannot send NTLMv1, so the attempt needs its own login client and a test account.'
    Add-Detail 'Until then, N1 (this machine) and N2 (no NTLMv1 logons) show the configuration side.'
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'needs its own NTLMv1 login client, which is not built yet.'
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
