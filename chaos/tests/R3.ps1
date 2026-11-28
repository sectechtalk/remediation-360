# uses: Reg
$v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS'
Add-Detail "EnableMDNS = $(if ($null -eq $v) { 'not set' } else { $v })"
if ($v -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'mDNS is off.' }
Write-Verdict -Verdict 'FAIL' -Summary 'mDNS is on (EnableMDNS is not 0).'
