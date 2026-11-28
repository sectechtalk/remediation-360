# uses: Reg, Event
$send = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic'
Add-Detail "RestrictSendingNTLMTraffic = $(if ($null -eq $send) { 'not set' } else { $send })"
if ($send -eq 2) { Write-Verdict -Verdict 'PASS' -Summary 'outgoing NTLM is blocked (RestrictSendingNTLMTraffic = 2).' }
if ($send -ne 1) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'outgoing NTLM is not audited (N4), so NTLM use is not logged here.' }
$events = Get-RecentEvent -LogName 'Microsoft-Windows-NTLM/Operational' -Id 8001 -Since (Get-Date).AddDays(-7) -MaxEvents 2000
if ($events.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no outgoing NTLM in the last 7 days (NTLM event 8001).' }
$servers = @($events | ForEach-Object { [string]$_.Properties[0].Value } | Where-Object { $_ } | Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 15 | ForEach-Object { "$($_.Name) ($($_.Count))" })
Add-Detail "Servers it used NTLM with: $($servers -join ', ')"
Write-Verdict -Verdict 'FAIL' -Summary "$($events.Count) outgoing NTLM login(s) in the last 7 days."
