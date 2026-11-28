# uses: Ad, Ca, Pki
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$tpls = @(Get-PublishedTemplate -Context $ctx)
if (@(Get-EnterpriseCa -Context $ctx).Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no enterprise CA is published in AD, so no template can be enrolled in.' }
Add-Detail "Templates published on a CA: $($tpls.Count)"
$bad = @($tpls | Where-Object { (Test-LoginEku -Eku $_.Eku) -and $_.SuppliesSubject -and $_.LowEnrollers.Count -gt 0 -and -not $_.Approval -and $_.RaSignatures -eq 0 })
foreach ($t in $bad) { Add-Detail "$($t.Name) (on $($t.Cas)): enroll $(Format-SidList -Sid $t.LowEnrollers)" }
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) template(s) let anyone enroll as someone else (ESC1): $(($bad | ForEach-Object { $_.Name }) -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'no published template lets a low-privilege user pick the subject of a login certificate.'
