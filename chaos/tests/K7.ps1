# uses: Ad, Sysvol
# The KDC reads DefaultDomainSupportedEncTypes from the registry on each DC. Group Policy can push it (security
# template, Registry.pol or a Preferences registry item); those copies are read here from SYSVOL. A value set by hand on
# a DC can only be seen on that DC.
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$found = @()
foreach ($g in Get-DcGpoPath -Context $ctx) {
    $gpo = Split-Path -Path $g -Leaf
    foreach ($line in Get-GpoSecurityLine -GpoPath $g) { if ($line -match 'Services\\KDC\\DefaultDomainSupportedEncTypes\s*=\s*\d+,(\d+)') { $found += [pscustomobject]@{ Gpo = $gpo; Value = [int64]$Matches[1] } } }
    foreach ($e in Get-GpoRegistryPol -GpoPath $g) { if ($e.Name -eq 'DefaultDomainSupportedEncTypes' -and $e.Key -like '*Services\KDC') { $found += [pscustomobject]@{ Gpo = $gpo; Value = [int64]$e.Data } } }
    foreach ($e in Get-GpoPreferenceRegistry -GpoPath $g) { if ($e.Name -eq 'DefaultDomainSupportedEncTypes' -and $e.Action -ne 'D') { $found += [pscustomobject]@{ Gpo = $gpo; Value = [Convert]::ToInt64([string]$e.Value, 16) } } }
}
if ($found.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no GPO sets DefaultDomainSupportedEncTypes; a value set by hand on a DC can only be seen on the DC itself.' }
$found | ForEach-Object { Add-Detail "GPO $($_.Gpo): DefaultDomainSupportedEncTypes = 0x$('{0:X}' -f $_.Value)" }
$rc4 = @($found | Where-Object { $_.Value -band 4 })
if ($rc4.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "a GPO sets a domain-wide RC4 override: $(($rc4 | ForEach-Object { $_.Gpo }) -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'the GPOs that set DefaultDomainSupportedEncTypes leave RC4 out.'
