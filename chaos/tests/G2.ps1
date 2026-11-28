# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$d = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(objectClass=*)' -Property 'ms-ds-machineaccountquota' -Scope Base)[0]
$q = $d.'ms-ds-machineaccountquota'
if ($null -ne $q -and [int]$q -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'ms-DS-MachineAccountQuota is 0.' }
Write-Verdict -Verdict 'FAIL' -Summary "any user can add $(if ($null -eq $q) { 'computers (quota not readable)' } else { "$q computers" }) to the domain (ms-DS-MachineAccountQuota)."
