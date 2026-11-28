# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$found = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Property 'samaccountname' | ForEach-Object { [string]$_.samaccountname })
if ($found.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($found.Count) enabled account(s) do not need Kerberos pre-authentication: $((@($found) | Select-Object -First 25) -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'every enabled account needs Kerberos pre-authentication.'
