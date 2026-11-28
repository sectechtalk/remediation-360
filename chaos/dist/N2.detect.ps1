# STT - Chaos - N2 No NTLMv1 logons
# Configuration check: this machine (NTLM). Proves: Nothing used NTLMv1 here in the last 7 days.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/N2.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

$script:ChaosId = 'N2'
try {
    # Counts successful logons (Security event 4624) that used NTLM V1 in the last 7 days.
    $xpath = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= 604800000]]] and *[EventData[Data[@Name='LmPackageName']='NTLM V1']]"
    try {
        $events = @(Get-WinEvent -LogName 'Security' -FilterXPath $xpath -MaxEvents 1000 -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { $events = @() } else { throw }
    }
    if ($events.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no NTLMv1 logon in the Security log in the last 7 days.' }
    $from = @($events | ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'WorkstationName' } | ForEach-Object { $_.'#text' } } | Where-Object { $_ } | Sort-Object -Unique)
    Add-Detail "From workstations: $(($from | Select-Object -First 10) -join ', ')"
    Write-Verdict -Verdict 'FAIL' -Summary "$($events.Count) NTLMv1 logon(s) in the last 7 days."
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
