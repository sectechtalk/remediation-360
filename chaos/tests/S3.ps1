# uses: Ad, Ca, Smb
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$targets = @(Get-EnterpriseCa -Context $ctx | ForEach-Object { [string]$_.dnshostname } | Where-Object { $_ } | Sort-Object -Unique)
if ($targets.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no enterprise CA is published in AD, so there is nothing to relay to.' }
$bad = @(); $unreachable = @()
foreach ($t in $targets) {
    $mode = Get-SmbSigningMode -Target $t
    Add-Detail "${t}: SMB signing $mode"
    if ($mode -eq 'not required') { $bad += $t } elseif ($mode -eq 'unreachable') { $unreachable += $t }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) of $($targets.Count) CAs do not require SMB signing: $($bad -join ', ')." }
if ($unreachable.Count -gt 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary "no SMB answer from $($unreachable -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary "all $($targets.Count) CAs require SMB signing."
