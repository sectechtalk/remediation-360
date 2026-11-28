# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$dmsa = Get-SchemaGuid -Context $ctx -LdapName 'msDS-DelegatedManagedServiceAccount'
$dc2025 = @(Get-DomainController -Context $ctx | Where-Object { [string]$_.operatingsystem -like '*2025*' } | ForEach-Object { [string]$_.name })
Add-Detail "DCs on Server 2025: $(if ($dc2025.Count) { $dc2025 -join ', ' } else { 'none' })"
if ($null -eq $dmsa) { Write-Verdict -Verdict 'PASS' -Summary 'the schema has no dMSA class (no Server 2025 schema), so BadSuccessor is not possible.' }
$allowed = Get-AdminSid -Context $ctx
$r = [System.DirectoryServices.ActiveDirectoryRights]
$found = @{}
foreach ($ou in Find-AdObject -SearchBase $ctx.DomainDn -Filter '(|(objectClass=organizationalUnit)(objectClass=container))' -Property 'distinguishedname' -WithAcl) {
    foreach ($rule in (Get-AdAclRule -AdObject $ou).Rules) {
        if ($allowed -contains $rule.IdentityReference.Value) { continue }
        $create = ($rule.ActiveDirectoryRights -band ($r::GenericAll -bor $r::CreateChild)) -and ($rule.ObjectType -eq [guid]::Empty -or $rule.ObjectType -eq $dmsa)
        if ($create) { $found["$(Resolve-SidName -Sid $rule.IdentityReference.Value) can create in $(($ou.distinguishedname -split ',')[0])"] = $true }
    }
}
foreach ($m in Find-AdObject -SearchBase $ctx.DomainDn -Filter '(objectClass=msDS-DelegatedManagedServiceAccount)' -Property 'samaccountname' -WithAcl) {
    foreach ($rule in (Get-AdAclRule -AdObject $m).Rules) {
        if ($allowed -notcontains $rule.IdentityReference.Value -and (Test-WriteRule -Rule $rule)) { $found["$(Resolve-SidName -Sid $rule.IdentityReference.Value) can write dMSA $($m.samaccountname)"] = $true }
    }
}
$found.Keys | Sort-Object | Select-Object -First 20 | ForEach-Object { Add-Detail $_ }
if ($found.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($found.Count) non-admin right(s) to create or change a dMSA (BadSuccessor)$(if (-not $dc2025.Count) { '; exploitable once a DC runs Server 2025' })." }
Write-Verdict -Verdict 'PASS' -Summary 'only admin groups can create or change a dMSA.'
