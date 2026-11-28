# uses:
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
