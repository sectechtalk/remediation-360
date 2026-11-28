# uses: Ad, Sync
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$accounts = @(Get-SyncAccount -Context $ctx | Where-Object { $_.samaccountname -like 'MSOL_*' })
if ($accounts.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no MSOL_ connector account was found (a custom connector account is not detected).' }
$allowed = @('S-1-5-18', 'S-1-5-10', 'S-1-5-32-544', "$($ctx.DomainSid)-512", "$($ctx.ForestSid)-519")
$bad = @()
foreach ($a in $accounts) {
    $acl = Get-AdAclRule -AdObject $a
    $why = @()
    if (-not $acl.Descriptor.AreAccessRulesProtected) { $why += 'inheritance on' }
    $writers = @($acl.Rules | Where-Object { $allowed -notcontains $_.IdentityReference.Value -and (Test-WriteRule -Rule $_) } | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
    if ($writers.Count) { $why += "writable by $(Format-SidList -Sid $writers)" }
    Add-Detail "$($a.samaccountname): $(if ($why.Count) { $why -join '; ' } else { 'locked down' })"
    if ($why.Count) { $bad += [string]$a.samaccountname }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad -join ', ') is not locked down as Set-ADSyncRestrictedPermissions sets it." }
Write-Verdict -Verdict 'PASS' -Summary 'the sync connector account has inheritance off and only admins can change it.'
