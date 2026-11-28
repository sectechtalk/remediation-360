# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$bad = @()
foreach ($o in Find-AdObject -SearchBase $ctx.DomainDn -Filter '(altSecurityIdentities=*)' -Property 'samaccountname', 'altsecurityidentities') {
    foreach ($v in @($o.altsecurityidentities)) {
        $s = [string]$v
        if ($s -notmatch '^X509:') { continue }
        $weak = ($s -match '<RFC822>') -or ($s -match '<S>' -and $s -notmatch '<SR>|<SKI>|<SHA1-PUKEY>')
        if ($weak) { $bad += "$($o.samaccountname): $(($s -split '<')[0..2] -join '<')..." }
    }
}
if ($bad.Count -gt 0) { $bad | Select-Object -First 20 | ForEach-Object { Add-Detail $_ }; Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) weak certificate mapping(s) (Issuer+Subject, Subject only or RFC822)." }
Write-Verdict -Verdict 'PASS' -Summary 'no account uses a weak certificate mapping.'
