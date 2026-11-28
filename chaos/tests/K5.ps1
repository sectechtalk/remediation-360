# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$groupDn = { param($Sid) $g = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter "(objectSid=$Sid)" -Property 'distinguishedname'); if ($g.Count) { [string]$g[0].distinguishedname } }
$protected = & $groupDn "$($ctx.DomainSid)-525"
$admins = @{}
foreach ($sid in @("$($ctx.DomainSid)-512", "$($ctx.ForestSid)-519", 'S-1-5-32-544')) {
    $dn = & $groupDn $sid
    if (-not $dn) { continue }
    foreach ($u in Find-AdObject -SearchBase $ctx.DomainDn -Filter "(&(samAccountType=805306368)(memberOf:1.2.840.113556.1.4.1941:=$dn)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -Property 'samaccountname', 'useraccountcontrol', 'memberof') { $admins[[string]$u.samaccountname] = $u }
}
if ($admins.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no enabled admin account was found.' }
$weak = @()
foreach ($name in $admins.Keys) {
    $u = $admins[$name]
    $sensitive = ([int64]$u.useraccountcontrol -band 0x100000) -ne 0
    $inProtected = $false
    if ($protected) { $inProtected = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter "(&(sAMAccountName=$name)(memberOf:1.2.840.113556.1.4.1941:=$protected))").Count -gt 0 }
    if (-not ($sensitive -or $inProtected)) { $weak += $name }
}
Add-Detail "Enabled Domain, Enterprise and built-in Admins: $($admins.Count)"
if ($weak.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($weak.Count) admin(s) are neither in Protected Users nor marked sensitive: $((@($weak) | Select-Object -First 25) -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary "all $($admins.Count) admins are in Protected Users or cannot be delegated."
