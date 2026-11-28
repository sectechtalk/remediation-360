# uses: Reg
$v = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy'
Add-Detail "LocalAccountTokenFilterPolicy = $(if ($null -eq $v) { 'not set' } else { $v })"
if ($null -eq $v -or $v -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'remote UAC filters local admin logins over the network.' }
Write-Verdict -Verdict 'FAIL' -Summary 'local admins get full rights over the network (LocalAccountTokenFilterPolicy = 1).'
