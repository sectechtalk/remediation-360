# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$found = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=4128)(!(lastLogonTimestamp=*)))' -Property 'name' | ForEach-Object { [string]$_.name })
if ($found.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($found.Count) pre-Windows 2000 computer account(s) that never signed in: $((@($found) | Select-Object -First 25) -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'no never-used computer account is flagged password-not-required.'
