# uses: Ad
# Forcing an RC4-only ticket request needs its own login client. Until it is built, this asks each DC for a normal
# service ticket (klist get) and fails if any ticket this machine holds is RC4: that proves a DC still issues RC4.
# Seeing no RC4 ticket is not proof of refusal, so that case is COULD NOT TEST, never PASS.
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$dcs = @(Get-DomainController -Context $ctx)
if ($dcs.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no domain controller was found in AD.' }
foreach ($dc in $dcs) {
    if ($dc.dnshostname) { $null = & klist.exe get "ldap/$($dc.dnshostname)" 2>&1 }
}
$text = & klist.exe 2>&1 | Out-String
$tickets = @($text -split '(?m)^#\d+>' | Select-Object -Skip 1)
$rc4 = @($tickets | Where-Object { $_ -match 'KerbTicket Encryption Type:\s*RSADSI RC4' } | ForEach-Object { if ($_ -match 'Server:\s*(\S+)') { $Matches[1] } })
Add-Detail "Tickets held by this computer: $($tickets.Count); RC4: $($rc4.Count)"
if ($rc4.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "a DC issued RC4 service tickets for $($rc4 -join ', ')." }
Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no RC4 ticket seen, but proving refusal needs its own RC4-only login client, which is not built yet.'
