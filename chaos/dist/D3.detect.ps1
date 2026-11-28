# STT - Chaos - D3 Printers offer no cleartext protocols
# Active probe (Printers). Proves: Printer admin and file transfer are encrypted.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/D3.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

#region Net
# The first IPv4 address of a host name, or $null.
function Resolve-HostIPv4 {
    param([Parameter(Mandatory = $true)][string]$Name)
    try {
        $a = [System.Net.Dns]::GetHostAddresses($Name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
        if ($a) { return $a.IPAddressToString }
    } catch {
        $null = $_
    }
    return $null
}

# True when a TCP port accepts a connection within the timeout.
function Test-TcpPort {
    param([Parameter(Mandatory = $true)][string]$Target, [Parameter(Mandatory = $true)][int]$Port, [int]$TimeoutMs = 2000)
    $c = New-Object -TypeName System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($Target, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $c.EndConnect($iar)
        return $true
    } catch {
        $null = $_
        return $false
    } finally {
        $c.Close()
    }
}
#endregion

#region Http
# One HTTP(S) GET without following redirects. The certificate is always checked; an untrusted one shows as an error.
function Get-HttpAnswer {
    param([Parameter(Mandatory = $true)][string]$Uri, [switch]$UseDefaultCredential)
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    $req = [System.Net.HttpWebRequest]::Create($Uri)
    $req.Method = 'GET'
    $req.Timeout = 10000
    $req.AllowAutoRedirect = $false
    if ($UseDefaultCredential) { $req.UseDefaultCredentials = $true }
    $resp = $null
    try {
        $resp = $req.GetResponse()
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { return [pscustomobject]@{ Status = 0; Error = [string]$_.Exception.Status; Auth = @(); Location = $null } }
    }
    try {
        $auth = @($resp.Headers.GetValues('WWW-Authenticate') | Where-Object { $_ })
        [pscustomobject]@{ Status = [int]$resp.StatusCode; Error = $null; Auth = $auth; Location = $resp.Headers['Location'] }
    } finally {
        $resp.Close()
    }
}
#endregion

$script:ChaosId = 'D3'
try {
    # Checks each network printer for FTP (21), Telnet (23) and TFTP (69), and whether its web page on port 80 sends you on
    # to HTTPS. The TFTP check asks for a file that does not exist; any answer, even "file not found", means TFTP is on.
    function Test-TftpOpen {
        param([Parameter(Mandatory = $true)][string]$Target)
        [byte[]]$rrq = @(0x00, 0x01) + [System.Text.Encoding]::ASCII.GetBytes('chaos-monkey-probe.txt') + @(0x00) + [System.Text.Encoding]::ASCII.GetBytes('octet') + @(0x00)
        $u = New-Object -TypeName System.Net.Sockets.UdpClient
        try {
            $u.Client.ReceiveTimeout = 2000
            $u.Connect($Target, 69)
            $null = $u.Send($rrq, $rrq.Length)
            $from = New-Object -TypeName System.Net.IPEndPoint -ArgumentList ([System.Net.IPAddress]::Any), 0
            $null = $u.Receive([ref]$from)
            return $true
        } catch {
            $null = $_
            return $false
        } finally {
            $u.Close()
        }
    }
    $targets = @(Get-PrinterPort -ErrorAction SilentlyContinue | Where-Object { $_.PrinterHostAddress } | ForEach-Object { [string]$_.PrinterHostAddress } | Sort-Object -Unique)
    if ($targets.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'this machine uses no network printer through a TCP/IP port.' }
    $bad = @()
    foreach ($t in $targets) {
        $open = @()
        if (Test-TcpPort -Target $t -Port 21) { $open += 'FTP' }
        if (Test-TcpPort -Target $t -Port 23) { $open += 'Telnet' }
        if (Test-TftpOpen -Target $t) { $open += 'TFTP' }
        if (Test-TcpPort -Target $t -Port 80) {
            $a = Get-HttpAnswer -Uri "http://$t/"
            if (-not ($a.Status -in 301, 302, 303, 307, 308 -and [string]$a.Location -like 'https://*')) { $open += "web admin over HTTP (HTTP $($a.Status))" }
        }
        Add-Detail "${t}: $(if ($open.Count) { $open -join ', ' } else { 'no cleartext service' })"
        if ($open.Count -gt 0) { $bad += $t }
    }
    if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) of $($targets.Count) printers offer cleartext services: $($bad -join ', ')." }
    Write-Verdict -Verdict 'PASS' -Summary "none of the $($targets.Count) printers offer FTP, Telnet, TFTP or plain HTTP admin."
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
