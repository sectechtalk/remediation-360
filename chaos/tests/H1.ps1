# uses: Ad, Sync
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$getChangesAll = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
$sync = @(Get-SyncAccount -Context $ctx)
$allowed = @('S-1-5-18', 'S-1-5-9', 'S-1-5-32-544', "$($ctx.DomainSid)-512", "$($ctx.DomainSid)-516", "$($ctx.DomainSid)-521", "$($ctx.ForestSid)-519", "$($ctx.ForestSid)-498") + @($sync | ForEach-Object { ConvertTo-SidString -Bytes $_.objectsid })
$root = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(objectClass=*)' -Scope Base -WithAcl)[0]
$r = [System.DirectoryServices.ActiveDirectoryRights]
$holders = @((Get-AdAclRule -AdObject $root).Rules | Where-Object {
    ($_.ActiveDirectoryRights -band $r::GenericAll) -or (($_.ActiveDirectoryRights -band $r::ExtendedRight) -and ($_.ObjectType -eq [guid]::Empty -or $_.ObjectType -eq $getChangesAll))
} | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
Add-Detail "Can DCSync: $(Format-SidList -Sid $holders)"
$extra = @($holders | Where-Object { $allowed -notcontains $_ })
if ($extra.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "unexpected accounts can DCSync: $(Format-SidList -Sid $extra)." }
Write-Verdict -Verdict 'PASS' -Summary 'only DCs, admin groups and the sync account can DCSync.'
