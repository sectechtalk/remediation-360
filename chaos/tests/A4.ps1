# uses: Ad, Ca
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$pks = "CN=Public Key Services,CN=Services,$($ctx.ConfigDn)"
$objects = @(Find-AdObject -SearchBase $pks -Filter '(objectClass=*)' -Property 'distinguishedname', 'objectclass' -Scope Base -WithAcl)
$objects += @(Find-AdObject -SearchBase $pks -Filter '(|(objectClass=container)(objectClass=certificationAuthority)(objectClass=msPKI-Enterprise-Oid))' -Property 'distinguishedname', 'objectclass' -Scope OneLevel -WithAcl)
foreach ($ca in Get-EnterpriseCa -Context $ctx) {
    if ($ca.dnshostname) { $objects += @(Find-AdObject -SearchBase $ctx.DomainDn -Filter "(&(objectCategory=computer)(dNSHostName=$($ca.dnshostname)))" -Property 'distinguishedname', 'objectclass' -WithAcl) }
}
$low = Get-LowPrivilegeSid -Context $ctx
$bad = @()
foreach ($o in $objects) {
    $acl = Get-AdAclRule -AdObject $o
    $writers = @($acl.Rules | Where-Object { $low -contains $_.IdentityReference.Value -and (Test-WriteRule -Rule $_ -CreateChild) } | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
    if ($low -contains $acl.Owner) { $writers += $acl.Owner }
    if ($writers.Count -gt 0) { $bad += $o.distinguishedname; Add-Detail "$(($o.distinguishedname -split ',')[0]): writable by $(Format-SidList -Sid $writers)" }
}
Add-Detail "PKI objects checked: $($objects.Count)"
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) PKI object(s) can be changed by low-privilege users (ESC5)." }
Write-Verdict -Verdict 'PASS' -Summary "none of the $($objects.Count) PKI containers, NTAuth store or CA computer objects can be changed by low-privilege users."
