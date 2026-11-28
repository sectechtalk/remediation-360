# STT - Chaos - W5 LAPS password is long and complex
# Configuration check: this machine (Windows LAPS). Proves: The local admin password cannot be guessed.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/W5.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

$script:ChaosId = 'W5'
try {
    $p = Get-LapsPolicy
    if ($null -eq $p) { Write-Verdict -Verdict 'FAIL' -Summary 'no LAPS policy reaches this machine.' }
    $length = [int](Get-LapsSetting -Policy $p -Name 'PasswordLength' -Default 14)
    $complexity = [int](Get-LapsSetting -Policy $p -Name 'PasswordComplexity' -Default 4)
    $words = [int](Get-LapsSetting -Policy $p -Name 'PassphraseLength' -Default 6)
    Add-Detail "Policy from $($p.Source); PasswordLength = $length; PasswordComplexity = $complexity; PassphraseLength = $words"
    if ($complexity -in 6, 7, 8) {
        if ($words -ge 6) { Write-Verdict -Verdict 'PASS' -Summary "a passphrase of $words words." }
        Write-Verdict -Verdict 'FAIL' -Summary "the passphrase has only $words words (6 or more needed)."
    }
    if ($length -ge 14 -and $complexity -ge 4) { Write-Verdict -Verdict 'PASS' -Summary "$length characters with all four character types." }
    Write-Verdict -Verdict 'FAIL' -Summary "the password is too weak ($length characters, complexity $complexity; 14 and 4 needed)."
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
