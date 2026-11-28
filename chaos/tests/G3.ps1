# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$k = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(sAMAccountName=krbtgt)' -Property 'pwdlastset')
$set = if ($k.Count) { ConvertFrom-FileTime -Value $k[0].pwdlastset } else { $null }
if ($null -eq $set) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'the krbtgt password date could not be read.' }
$days = [int]((Get-Date).ToUniversalTime() - $set).TotalDays
if ($days -le 180) { Write-Verdict -Verdict 'PASS' -Summary "the krbtgt password was changed $days days ago ($($set.ToString('yyyy-MM-dd')))." }
Write-Verdict -Verdict 'FAIL' -Summary "the krbtgt password is $days days old ($($set.ToString('yyyy-MM-dd'))); our limit is 180."
