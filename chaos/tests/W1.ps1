# uses: Ad
# As SYSTEM this runs as the computer account. It asks a DC for the LAPS password attributes of up to 20 other
# computers that have a LAPS password. A hardened domain returns them empty.
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$self = "$env:COMPUTERNAME$"
$filter = "(&(objectCategory=computer)(|(msLAPS-PasswordExpirationTime=*)(ms-Mcs-AdmPwdExpirationTime=*))(!(sAMAccountName=$self)))"
$others = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter $filter -Property 'name', 'ms-mcs-admpwd', 'mslaps-password', 'mslaps-encryptedpassword' -SizeLimit 20)
if ($others.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no other computer keeps a LAPS password in AD (backed up to Entra or not used), so there is nothing to read.' }
$readable = @($others | Where-Object { $_.'ms-mcs-admpwd' -or $_.'mslaps-password' -or $_.'mslaps-encryptedpassword' } | ForEach-Object { [string]$_.name })
Add-Detail "Asked for the LAPS password of $($others.Count) other computers."
if ($readable.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "this computer can read the LAPS password of $($readable.Count) other computers: $($readable -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary "every one of the $($others.Count) LAPS password values came back empty."
