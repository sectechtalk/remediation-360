# uses: Ad, Sync, Net, NtlmShare
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
if (Test-OutgoingNtlmBlocked) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine blocks outgoing NTLM itself (N5 or V2), so it cannot tell whether the target refuses it.' }
$targets = @(Get-SyncServer -Context $ctx)
if ($targets.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no Entra sync server was found in AD (MSOL_ account description or sync gMSA).' }
$accepted = @(); $unreachable = @()
foreach ($t in $targets) {
    $ip = Resolve-HostIPv4 -Name $t
    if (-not $ip) { Add-Detail "${t}: no IPv4 address"; $unreachable += $t; continue }
    $r = Test-NtlmShare -Address $ip -Share 'IPC$'
    Add-Detail "$t ($ip): NTLM login $r"
    if ($r -eq 'accepted') { $accepted += $t } elseif ($r -like 'unreachable*') { $unreachable += $t }
}
if ($accepted.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "NTLM login accepted by $($accepted -join ', ')." }
if ($unreachable.Count -gt 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary "could not reach $($unreachable -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary "all $($targets.Count) sync servers refused an NTLM login."
