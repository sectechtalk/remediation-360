# uses: Ad
# Groups allowed to read LAPS passwords besides the admin groups. Put their names (DOMAIN\Group) here before you create
# the change; with an empty list every non-admin reader is reported.
$AllowedReaders = @()
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$attrs = @('ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-EncryptedDSRMPassword') | ForEach-Object { Get-SchemaGuid -Context $ctx -LdapName $_ } | Where-Object { $_ }
if (@($attrs).Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'the schema has no LAPS password attributes, so there is nothing to read.' }
$computerClass = [guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
$allowed = @(Get-AdminSid -Context $ctx) + @($AllowedReaders | ForEach-Object { (New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $_).Translate([System.Security.Principal.SecurityIdentifier]).Value })
$containers = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(|(objectClass=organizationalUnit)(objectClass=domainDNS))' -Property 'distinguishedname' -WithAcl)
$containers += @(Find-AdObject -SearchBase "CN=Computers,$($ctx.DomainDn)" -Filter '(objectClass=*)' -Property 'distinguishedname' -Scope Base -WithAcl)
$r = [System.DirectoryServices.ActiveDirectoryRights]
$readers = @{}
foreach ($c in $containers) {
    foreach ($rule in (Get-AdAclRule -AdObject $c -IncludeInheritOnly).Rules) {
        if ($allowed -contains $rule.IdentityReference.Value) { continue }
        if ($rule.InheritedObjectType -ne [guid]::Empty -and $rule.InheritedObjectType -ne $computerClass) { continue }
        $rights = $rule.ActiveDirectoryRights
        $all = ($rights -band $r::GenericAll) -or (($rights -band $r::ExtendedRight) -and $rule.ObjectType -eq [guid]::Empty)
        $attr = ($rights -band ($r::ExtendedRight -bor $r::ReadProperty)) -and ($attrs -contains $rule.ObjectType)
        if ($all -or $attr) {
            $sid = $rule.IdentityReference.Value
            if (-not $readers.ContainsKey($sid)) { $readers[$sid] = New-Object -TypeName System.Collections.Generic.List[string] }
            if ($readers[$sid].Count -lt 3) { $readers[$sid].Add((($c.distinguishedname -split ',')[0])) }
        }
    }
}
foreach ($sid in $readers.Keys) { Add-Detail "$(Resolve-SidName -Sid $sid) can read LAPS passwords on $($readers[$sid] -join ', ')" }
if ($readers.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($readers.Count) group(s) or account(s) outside the allow list can read LAPS passwords." }
Write-Verdict -Verdict 'PASS' -Summary "only admin groups$(if ($AllowedReaders.Count) { ' and ' + ($AllowedReaders -join ', ') }) can read LAPS passwords."
