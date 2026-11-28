# uses: Reg
$root = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
$adapters = @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'Tcpip_*' })
if ($adapters.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'NetBIOS over TCP/IP is not bound to any adapter.' }
$on = @()
foreach ($a in $adapters) {
    $v = Get-RegValue -Path $a.PSPath -Name 'NetbiosOptions'
    if ($v -ne 2) { $on += "$($a.PSChildName -replace '^Tcpip_', '') = $(if ($null -eq $v) { 'not set' } else { $v })" }
}
if ($on.Count -gt 0) { $on | Select-Object -First 15 | ForEach-Object { Add-Detail $_ }; Write-Verdict -Verdict 'FAIL' -Summary "NetBIOS is not off on $($on.Count) of $($adapters.Count) adapters (0 = from DHCP, 1 = on)." }
Write-Verdict -Verdict 'PASS' -Summary "NetBIOS is off on all $($adapters.Count) adapters."
