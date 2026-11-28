# uses: Ad, Ca
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$cas = @(Get-EnterpriseCa -Context $ctx)
if ($cas.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no enterprise CA is published in AD.' }
# Reads each CA's permissions with certutil and flags Manage CA or Manage Certificates held by a low-privilege group.
$lowNames = @(Get-LowPrivilegeSid -Context $ctx | ForEach-Object { Resolve-SidName -Sid $_ })
$bad = @(); $unknown = @()
foreach ($ca in $cas) {
    $out = & certutil.exe -config "$($ca.dnshostname)\$($ca.cn)" -getreg 'CA\Security' 2>&1
    if ($LASTEXITCODE -ne 0) { Add-Detail "$($ca.cn): could not read its permissions"; $unknown += [string]$ca.cn; continue }
    $manage = @($out | Where-Object { $_ -match 'Allow' -and $_ -match 'Manage' })
    $hits = @(foreach ($line in $manage) { foreach ($n in $lowNames) { if ($line -like "*$n*") { $line; break } } })
    Add-Detail "$($ca.cn): $($manage.Count) manage right(s)$(if ($hits.Count) { '; low-privilege: ' + (($hits | ForEach-Object { $_.Trim() -replace '\s+', ' ' }) -join '; ') })"
    if ($hits.Count -gt 0) { $bad += [string]$ca.cn }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "low-privilege groups can manage $($bad -join ', ') (ESC7)." }
if ($unknown.Count -gt 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary "could not read the permissions of $($unknown -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'only admin groups can manage the CAs or their certificates.'
