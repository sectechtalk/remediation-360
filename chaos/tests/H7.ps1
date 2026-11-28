# uses: Ad, Sync, Smb
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$targets = @(Get-SyncServer -Context $ctx)
if ($targets.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no Entra sync server was found in AD (MSOL_ account description or sync gMSA).' }
$bad = @(); $unreachable = @()
foreach ($t in $targets) {
    $mode = Get-SmbSigningMode -Target $t
    Add-Detail "${t}: SMB signing $mode"
    if ($mode -eq 'not required') { $bad += $t } elseif ($mode -eq 'unreachable') { $unreachable += $t }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) of $($targets.Count) sync servers do not require SMB signing: $($bad -join ', ')." }
if ($unreachable.Count -gt 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary "no SMB answer from $($unreachable -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary "all $($targets.Count) sync servers require SMB signing."
