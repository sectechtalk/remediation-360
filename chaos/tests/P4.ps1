# uses: Reg
$v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
Add-Detail "UseLogonCredential = $(if ($null -eq $v) { 'not set' } else { $v })"
if ($null -eq $v -or $v -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'WDigest keeps no cleartext passwords.' }
Write-Verdict -Verdict 'FAIL' -Summary 'WDigest is set to keep cleartext passwords in memory (UseLogonCredential = 1).'
