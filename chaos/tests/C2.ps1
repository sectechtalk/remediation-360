# uses:
$svc = Get-Service -Name 'WebClient' -ErrorAction SilentlyContinue
if ($null -eq $svc) { Write-Verdict -Verdict 'PASS' -Summary 'the WebClient service is not installed.' }
Add-Detail "WebClient: start type $($svc.StartType), $($svc.Status)"
if ($svc.StartType -eq 'Disabled') { Write-Verdict -Verdict 'PASS' -Summary 'the WebClient service is disabled.' }
Write-Verdict -Verdict 'FAIL' -Summary "the WebClient service is $($svc.StartType) and $($svc.Status)."
