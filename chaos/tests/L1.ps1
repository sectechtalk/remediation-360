# uses: Ad, Ldap
# A simple bind on port 389 with a made-up account name and a random secret. A DC that requires signing answers
# strongerAuthRequired (8) before it looks at the account; a DC that does not answers invalidCredentials (49).
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$dcs = @(Get-DomainController -Context $ctx)
if ($dcs.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no domain controller was found in AD.' }
$bad = @(); $unknown = @()
foreach ($dc in $dcs) {
    $r = Invoke-LdapBind -Server ([string]$dc.dnshostname) -Kind SimpleFake
    Add-Detail "$($dc.name): $r"
    if ($r -match '^error 8\b') { continue }
    if ($r -eq 'ok' -or $r -match '^error 49\b') { $bad += $dc.name } else { $unknown += $dc.name }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) of $($dcs.Count) DCs accept unsigned LDAP binds: $($bad -join ', ')." }
if ($unknown.Count -gt 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary "unexpected LDAP answer from $($unknown -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary "all $($dcs.Count) DCs refused an unsigned LDAP bind (strongerAuthRequired)."
