# uses: Ad, Ca, Pki
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$tpls = @(Get-PublishedTemplate -Context $ctx)
if (@(Get-EnterpriseCa -Context $ctx).Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no enterprise CA is published in AD, so no template can be enrolled in.' }
Add-Detail "Templates published on a CA: $($tpls.Count)"
$low = Get-LowPrivilegeSid -Context $ctx
$bad = @()
foreach ($t in $tpls) {
    $writers = @($t.Acl.Rules | Where-Object { $low -contains $_.IdentityReference.Value -and (Test-WriteRule -Rule $_) } | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
    if ($low -contains $t.Acl.Owner) { $writers += $t.Acl.Owner }
    if ($writers.Count -gt 0) { $bad += $t.Name; Add-Detail "$($t.Name): writable by $(Format-SidList -Sid $writers)" }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) template(s) can be rewritten by low-privilege users (ESC4): $($bad -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'no published template can be changed by low-privilege users.'
