# uses: Ad, Smb
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$targets = @(Get-DomainController -Context $ctx | ForEach-Object { [string]$_.dnshostname } | Where-Object { $_ })
if ($targets.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no domain controller was found in AD.' }
$bad = @(); $unreachable = @()
foreach ($t in $targets) {
    $mode = Get-SmbSigningMode -Target $t
    Add-Detail "${t}: SMB signing $mode"
    if ($mode -eq 'not required') { $bad += $t } elseif ($mode -eq 'unreachable') { $unreachable += $t }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) of $($targets.Count) DCs do not require SMB signing: $($bad -join ', ')." }
if ($unreachable.Count -gt 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary "no SMB answer from $($unreachable -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary "all $($targets.Count) DCs require SMB signing."
