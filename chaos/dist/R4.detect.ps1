# STT - Chaos - R4 WPAD cannot be hijacked
# Active probe (Name resolution). Proves: Nobody can pose as the proxy configuration server.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/R4.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

$script:ChaosId = 'R4'
try {
    # Asks for "wpad" over DNS and over LLMNR/NetBIOS (the hijack path), and checks that WinHTTP auto-detect is off.
    $problems = @()
    $suffix = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
    $names = @('wpad')
    if ($suffix -and $suffix -ne 'WORKGROUP') { $names += "wpad.$suffix" }
    foreach ($n in $names) {
        $dns = @(Resolve-DnsName -Name $n -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress })
        if ($dns.Count -gt 0) { $problems += "$n resolves in DNS to $(($dns.IPAddress | Sort-Object -Unique) -join ', ')" } else { Add-Detail "${n}: no DNS answer" }
    }
    $local = @(Resolve-DnsName -Name 'wpad' -LlmnrNetbiosOnly -QuickTimeout -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress })
    if ($local.Count -gt 0) { $problems += "wpad answered over LLMNR/NetBIOS from $(($local.IPAddress | Sort-Object -Unique) -join ', ')" } else { Add-Detail 'wpad: no LLMNR/NetBIOS answer' }
    $disableWpad = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad'
    $svcStart = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc' -Name 'Start'
    Add-Detail "WinHttp DisableWpad = $(if ($null -eq $disableWpad) { 'not set' } else { $disableWpad }); WinHttpAutoProxySvc start = $(if ($null -eq $svcStart) { 'not installed' } else { $svcStart })"
    if (-not ($disableWpad -eq 1 -or $svcStart -eq 4 -or $null -eq $svcStart)) { $problems += 'WinHTTP proxy auto-detect is on' }
    if ($problems.Count -gt 0) { $problems | ForEach-Object { Add-Detail $_ }; Write-Verdict -Verdict 'FAIL' -Summary ($problems -join '; ') }
    Write-Verdict -Verdict 'PASS' -Summary 'wpad does not resolve and WinHTTP proxy auto-detect is off.'
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
