# uses: Reg
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
