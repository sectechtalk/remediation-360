# uses: Reg
$v = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
Add-Detail "EnableMulticast = $(if ($null -eq $v) { 'not set' } else { $v })"
if ($v -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'LLMNR is turned off by policy.' }
Write-Verdict -Verdict 'FAIL' -Summary 'LLMNR is on (the "Turn off multicast name resolution" policy is not set).'
