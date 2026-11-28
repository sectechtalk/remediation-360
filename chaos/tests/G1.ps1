# uses: Ad, Ldap
# Binds anonymously to each DC and reads the domain object. Reading rootDSE anonymously is normal and not tested.
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$dcs = @(Get-DomainController -Context $ctx)
if ($dcs.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no domain controller was found in AD.' }
$bad = @(); $unknown = @()
foreach ($dc in $dcs) {
    $r = Invoke-LdapBind -Server ([string]$dc.dnshostname) -Kind Anonymous -SearchBase $ctx.DomainDn
    Add-Detail "$($dc.name): $r"
    if ($r -eq 'ok') { $bad += $dc.name } elseif ($r -match '^error (81|91)\b') { $unknown += $dc.name }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) of $($dcs.Count) DCs let an anonymous login read the domain: $($bad -join ', ')." }
if ($unknown.Count -gt 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary "could not reach $($unknown -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary "all $($dcs.Count) DCs refused an anonymous search of the domain."
