# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$found = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516))(!(primaryGroupID=521)))' -Property 'samaccountname' | ForEach-Object { [string]$_.samaccountname })
if ($found.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($found.Count) non-DC account(s) trusted for unconstrained delegation: $((@($found) | Select-Object -First 25) -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'only domain controllers are trusted for unconstrained delegation.'
