# uses: Reg
$v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientIntegrity'
Add-Detail "LDAPClientIntegrity = $(if ($null -eq $v) { 'not set (Windows default 1, negotiate signing)' } else { $v })"
if ($null -eq $v -or $v -ge 1) { Write-Verdict -Verdict 'PASS' -Summary "LDAP client signing is $(if ($v -eq 2) { 'required' } else { 'negotiated' })." }
Write-Verdict -Verdict 'FAIL' -Summary 'LDAP client signing is off (LDAPClientIntegrity = 0).'
