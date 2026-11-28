# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
if ($null -eq (Get-SchemaGuid -Context $ctx -LdapName 'msLAPS-PasswordExpirationTime')) { Write-Verdict -Verdict 'FAIL' -Summary 'the schema has no Windows LAPS attributes, so no DSRM password is managed.' }
$dcs = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(&(objectCategory=computer)(primaryGroupID=516))' -Property 'name', 'mslaps-passwordexpirationtime')
$missing = @($dcs | Where-Object { $null -eq $_.'mslaps-passwordexpirationtime' } | ForEach-Object { [string]$_.name })
foreach ($d in $dcs) { $t = ConvertFrom-FileTime -Value $d.'mslaps-passwordexpirationtime'; Add-Detail "$($d.name): $(if ($t) { 'DSRM password expires ' + $t.ToString('yyyy-MM-dd') } else { 'no DSRM password expiry' })" }
if ($missing.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($missing.Count) of $($dcs.Count) DCs have no managed DSRM password: $($missing -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary "all $($dcs.Count) DCs back up a rotating DSRM password."
