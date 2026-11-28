# uses: Ad, Ca
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$cas = @(Get-EnterpriseCa -Context $ctx)
if ($cas.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no enterprise CA is published in AD.' }
$bad = @(); $unknown = @()
foreach ($ca in $cas) {
    $v = Get-CaRegistryDword -Ca $ca -Name 'policy\EditFlags'
    if ($null -eq $v) { Add-Detail "$($ca.cn): could not read policy\EditFlags"; $unknown += [string]$ca.cn; continue }
    Add-Detail "$($ca.cn): EditFlags = 0x$('{0:X}' -f $v)"
    if (($v -band 0x40000) -ne 0) { $bad += [string]$ca.cn }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad -join ', ') let requesters add any name (EDITF_ATTRIBUTESUBJECTALTNAME2, ESC6)." }
if ($unknown.Count -gt 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary "could not read the setting from $($unknown -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'no CA lets requesters add their own subject alternative name.'
