# uses:
$found = @('telnet.exe', 'tftp.exe' | Where-Object { Test-Path -LiteralPath (Join-Path -Path $env:SystemRoot -ChildPath "System32\$_") })
if ($found.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'neither the Telnet nor the TFTP client is installed.' }
Write-Verdict -Verdict 'FAIL' -Summary "installed: $($found -join ', ')."
