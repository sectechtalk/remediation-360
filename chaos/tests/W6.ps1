# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$found = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))' -Property 'name' | ForEach-Object { [string]$_.name })
if ($found.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($found.Count) computer(s) still use legacy LAPS (clear text in AD): $((@($found) | Select-Object -First 20) -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'no computer still has a legacy LAPS password in AD.'
