# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$f = @(Find-AdObject -SearchBase "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($ctx.ConfigDn)" -Filter '(objectClass=*)' -Property 'msds-enabledfeaturebl' -Scope Base)
if ($f.Count -gt 0 -and $f[0].'msds-enabledfeaturebl') { Write-Verdict -Verdict 'PASS' -Summary 'the AD Recycle Bin is on.' }
Write-Verdict -Verdict 'FAIL' -Summary 'the AD Recycle Bin is off.'
