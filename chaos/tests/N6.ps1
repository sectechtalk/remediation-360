# uses: Ad, Net, NtlmShare
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
if (Test-OutgoingNtlmBlocked) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine blocks outgoing NTLM itself (N5 or V2), so it cannot tell whether the DCs refuse it.' }
$dcs = @(Get-DomainController -Context $ctx)
if ($dcs.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no domain controller was found in AD.' }
$accepted = @(); $unreachable = @()
foreach ($dc in $dcs) {
    $ip = Resolve-HostIPv4 -Name ([string]$dc.dnshostname)
    if (-not $ip) { Add-Detail "$($dc.name): no IPv4 address"; $unreachable += $dc.name; continue }
    $r = Test-NtlmShare -Address $ip -Share 'NETLOGON'
    Add-Detail "$($dc.name) ($ip): NTLM login $r"
    if ($r -eq 'accepted') { $accepted += $dc.name } elseif ($r -like 'unreachable*') { $unreachable += $dc.name }
}
if ($accepted.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($accepted.Count) of $($dcs.Count) DCs accepted an NTLM login: $($accepted -join ', ')." }
if ($unreachable.Count -gt 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary "could not reach $($unreachable -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary "all $($dcs.Count) DCs refused an NTLM login."
