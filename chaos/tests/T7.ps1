# uses: Ad, Ca, Pki
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$tpls = @(Get-PublishedTemplate -Context $ctx)
if (@(Get-EnterpriseCa -Context $ctx).Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no enterprise CA is published in AD, so no template can be enrolled in.' }
Add-Detail "Templates published on a CA: $($tpls.Count)"
$bad = @()
foreach ($t in @($tpls | Where-Object { Test-LoginEku -Eku $_.Eku })) {
    Add-Detail "$($t.Name): enroll $(Format-SidList -Sid $t.Enrollers)$(if ($t.Approval) { ' (manager approval)' })"
    if ($t.LowEnrollers.Count -gt 0 -and -not $t.Approval) { $bad += $t.Name }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) login-capable template(s) are open to low-privilege groups without approval: $($bad -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'every login-capable template is limited to named groups or needs manager approval.'
