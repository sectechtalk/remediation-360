# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$found = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=4)' -Property 'samaccountname' | ForEach-Object { [string]$_.samaccountname })
if ($found.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($found.Count) account(s) explicitly allow RC4: $((@($found) | Select-Object -First 30) -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'no account explicitly allows RC4.'
