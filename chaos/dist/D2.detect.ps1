# STT - Chaos - D2 Printers refuse SNMP "public"
# Active probe (Printers). Proves: The printers this machine uses do not answer the default community.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/D2.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

$script:ChaosId = 'D2'
try {
    # One SNMP read of the device description (sysDescr) with community "public", in SNMP v1 and v2c, to each network
    # printer this machine prints to. Nothing is written.
    function Test-SnmpPublic {
        param([Parameter(Mandatory = $true)][string]$Target)
        $answered = $false
        foreach ($version in 0, 1) {
            $id = New-Object -TypeName byte[] -ArgumentList 4
            (New-Object -TypeName System.Random).NextBytes($id)
            $id[0] = $id[0] -band 0x7F
            [byte[]]$pdu = @(0x02, 0x04) + $id + @(0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00)
            [byte[]]$body = @(0x02, 0x01, $version, 0x04, 0x06) + [System.Text.Encoding]::ASCII.GetBytes('public') + @(0xA0, $pdu.Length) + $pdu
            [byte[]]$packet = @(0x30, $body.Length) + $body
            $u = New-Object -TypeName System.Net.Sockets.UdpClient
            try {
                $u.Client.ReceiveTimeout = 2000
                $u.Connect($Target, 161)
                $null = $u.Send($packet, $packet.Length)
                $from = New-Object -TypeName System.Net.IPEndPoint -ArgumentList ([System.Net.IPAddress]::Any), 0
                $null = $u.Receive([ref]$from)
                $answered = $true
            } catch {
                $null = $_
            } finally {
                $u.Close()
            }
            if ($answered) { break }
        }
        return $answered
    }
    $targets = @(Get-PrinterPort -ErrorAction SilentlyContinue | Where-Object { $_.PrinterHostAddress } | ForEach-Object { [string]$_.PrinterHostAddress } | Sort-Object -Unique)
    if ($targets.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'this machine uses no network printer through a TCP/IP port.' }
    $bad = @()
    foreach ($t in $targets) {
        $yes = Test-SnmpPublic -Target $t
        Add-Detail "${t}: $(if ($yes) { 'answers SNMP community public' } else { 'no answer to community public' })"
        if ($yes) { $bad += $t }
    }
    if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) of $($targets.Count) printers answer SNMP community public: $($bad -join ', ')." }
    Write-Verdict -Verdict 'PASS' -Summary "none of the $($targets.Count) printers answer SNMP community public."
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
