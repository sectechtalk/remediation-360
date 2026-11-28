# uses: Ad, Ca, Http
# Requests each CA's web enrollment page and CES address over plain HTTP, without logging in, and reads which logins
# the server offers. NTLM or Negotiate over HTTP is what an ESC8 relay needs.
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$cas = @(Get-EnterpriseCa -Context $ctx)
if ($cas.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no enterprise CA is published in AD, so there is no web enrollment.' }
$urls = foreach ($ca in $cas) {
    if ($ca.dnshostname) { "https://$($ca.dnshostname)/certsrv/" }
    foreach ($v in @($ca.'mspki-enrollment-servers')) { foreach ($m in [regex]::Matches([string]$v, 'https?://[^\s]+')) { $m.Value -replace '^http://', 'https://' } }
}
$urls = @($urls | Sort-Object -Unique)
$bad = @()
foreach ($u in $urls) {
    $http = $u -replace '^https://', 'http://'
    $a = Get-HttpAnswer -Uri $http
    if ($a.Status -eq 0) { Add-Detail "${http}: no answer ($($a.Error))"; continue }
    $offers = @($a.Auth | ForEach-Object { ($_ -split ' ')[0] })
    Add-Detail "${http}: HTTP $($a.Status)$(if ($offers.Count) { ', offers ' + ($offers -join '/') })$(if ($a.Location) { ', redirects to ' + $a.Location })"
    if ($offers | Where-Object { $_ -in 'NTLM', 'Negotiate' }) { $bad += $http }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "NTLM/Negotiate login offered over plain HTTP at $($bad -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'no CA web enrollment offers an NTLM/Negotiate login over plain HTTP.'
