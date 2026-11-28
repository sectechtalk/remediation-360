# uses: Ad, Sync
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$sync = @(Get-SyncAccount -Context $ctx)
if ($sync.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no Entra sync account exists in AD.' }
$sids = @($sync | ForEach-Object { ConvertTo-SidString -Bytes $_.objectsid })
$holder = @(Find-AdObject -SearchBase "CN=AdminSDHolder,CN=System,$($ctx.DomainDn)" -Filter '(objectClass=*)' -Scope Base -WithAcl)[0]
$hits = @((Get-AdAclRule -AdObject $holder).Rules | Where-Object { $sids -contains $_.IdentityReference.Value } | ForEach-Object { "$(Resolve-SidName -Sid $_.IdentityReference.Value): $($_.ActiveDirectoryRights)" } | Sort-Object -Unique)
if ($hits.Count -gt 0) { $hits | ForEach-Object { Add-Detail $_ }; Write-Verdict -Verdict 'FAIL' -Summary 'AdminSDHolder gives the sync account rights over admin accounts.' }
Write-Verdict -Verdict 'PASS' -Summary 'AdminSDHolder carries no permission for the sync account.'
