# uses: Net, Http
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
