# uses: Ad, Ca, Http
# Requests each CA's web enrollment page and CES address over HTTPS as this computer. The certificate must be one this
# machine trusts (it is never ignored) and the page must answer.
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$cas = @(Get-EnterpriseCa -Context $ctx)
if ($cas.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no enterprise CA is published in AD, so there is no web enrollment.' }
$urls = foreach ($ca in $cas) {
    if ($ca.dnshostname) { "https://$($ca.dnshostname)/certsrv/" }
    foreach ($v in @($ca.'mspki-enrollment-servers')) { foreach ($m in [regex]::Matches([string]$v, 'https?://[^\s]+')) { $m.Value -replace '^http://', 'https://' } }
}
$urls = @($urls | Sort-Object -Unique)
$works = @(); $bad = @()
foreach ($u in $urls) {
    $a = Get-HttpAnswer -Uri $u -UseDefaultCredential
    if ($a.Status -eq 0 -and $a.Error -eq 'ConnectFailure') { Add-Detail "${u}: not installed (no answer on 443)"; continue }
    if ($a.Status -eq 0) { Add-Detail "${u}: $($a.Error)"; $bad += "$u ($($a.Error))"; continue }
    Add-Detail "${u}: HTTP $($a.Status)"
    if ($a.Status -eq 404) { continue }
    if ($a.Status -ge 200 -and $a.Status -lt 400) { $works += $u } else { $bad += "$u (HTTP $($a.Status))" }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "HTTPS enrollment does not work at $($bad -join ', ')." }
if ($works.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no CA has web enrollment installed, so machines enroll over RPC (A3 checks that path).' }
Write-Verdict -Verdict 'PASS' -Summary "HTTPS enrollment answers with a trusted certificate at $($works.Count) address(es)."
