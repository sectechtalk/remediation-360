# uses: Ad, Ca, Pki
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$tpls = @(Get-PublishedTemplate -Context $ctx)
if (@(Get-EnterpriseCa -Context $ctx).Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no enterprise CA is published in AD, so no template can be enrolled in.' }
Add-Detail "Templates published on a CA: $($tpls.Count)"
$bad = @($tpls | Where-Object { $_.NoSecurityExt })
foreach ($t in $bad) { Add-Detail "$($t.Name) (on $($t.Cas)): CT_FLAG_NO_SECURITY_EXTENSION" }
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) template(s) leave out the strong mapping extension (ESC9): $(($bad | ForEach-Object { $_.Name }) -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'every published template carries the strong mapping (security) extension.'
