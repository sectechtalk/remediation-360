# STT - Chaos - N1 NTLMv1 disabled on this machine
# Configuration check: this machine (NTLM). Proves: This machine can neither send nor accept NTLMv1.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/N1.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

$script:ChaosId = 'N1'
try {
    $build = [int](Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuildNumber')
    Add-Detail "Windows build $build"
    if ($build -ge 26100) { Write-Verdict -Verdict 'PASS' -Summary "Windows build $build (Windows 11 24H2 / Server 2025 or later) has no NTLMv1 at all." }
    $lm = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
    $cli = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinClientSec'
    $srv = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinServerSec'
    Add-Detail "LmCompatibilityLevel = $(if ($null -eq $lm) { 'not set' } else { $lm }); NtlmMinClientSec = $(if ($null -eq $cli) { 'not set' } else { '0x{0:X8}' -f [int64]$cli }); NtlmMinServerSec = $(if ($null -eq $srv) { 'not set' } else { '0x{0:X8}' -f [int64]$srv })"
    $need = 0x20080000
    $ok = ($lm -eq 5) -and ($null -ne $cli) -and (([int64]$cli -band $need) -eq $need) -and ($null -ne $srv) -and (([int64]$srv -band $need) -eq $need)
    if ($ok) { Write-Verdict -Verdict 'PASS' -Summary 'LmCompatibilityLevel 5 with NTLMv2 session security and 128-bit required both ways.' }
    Write-Verdict -Verdict 'FAIL' -Summary 'this Windows still has NTLMv1 and is not set to refuse it (LmCompatibilityLevel 5, NtlmMinClientSec/NtlmMinServerSec 0x20080000).'
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
