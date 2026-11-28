# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$g = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(objectSid=S-1-5-32-554)' -Property 'member')
if ($g.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'the Pre-Windows 2000 Compatible Access group was not found.' }
$broad = @{ 'S-1-5-11' = 'Authenticated Users'; 'S-1-1-0' = 'Everyone'; 'S-1-5-7' = 'Anonymous Logon' }
$hits = @(foreach ($m in @($g[0].member)) { foreach ($sid in $broad.Keys) { if ([string]$m -like "CN=$sid,*") { $broad[$sid] } } })
Add-Detail "Members: $(@($g[0].member).Count)"
if ($hits.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "Pre-Windows 2000 Compatible Access contains $($hits -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'Pre-Windows 2000 Compatible Access holds no broad group.'
