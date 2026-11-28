# uses:
$svc = Get-Service -Name 'SNMP' -ErrorAction SilentlyContinue
if ($null -eq $svc) { Write-Verdict -Verdict 'PASS' -Summary 'the Windows SNMP service is not installed.' }
Write-Verdict -Verdict 'FAIL' -Summary "the Windows SNMP service is installed ($($svc.StartType), $($svc.Status))."
