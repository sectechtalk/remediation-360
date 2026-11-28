# uses: Reg, Ad, Sysvol
$audit = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AuditReceivingNTLMTraffic'
$send = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic'
Add-Detail "AuditReceivingNTLMTraffic = $(if ($null -eq $audit) { 'not set' } else { $audit }) (2 audits all incoming)"
Add-Detail "RestrictSendingNTLMTraffic = $(if ($null -eq $send) { 'not set' } else { $send }) (1 audits, 2 blocks outgoing)"
$problems = @()
if ($audit -ne 2) { $problems += 'incoming NTLM is not audited' }
if ($null -eq $send -or $send -lt 1) { $problems += 'outgoing NTLM is not audited' }
if (Test-DomainJoined) {
    $ctx = Get-AdContext
    $dc = @(Find-DcGpoRegistryValue -Context $ctx -Pattern 'Netlogon\\Parameters\\AuditNTLMInDomain')
    if ($dc.Count -eq 0) { $problems += 'no DC policy sets AuditNTLMInDomain'; Add-Detail 'DC policy AuditNTLMInDomain: not set in the GPOs linked to the domain or Domain Controllers OU' }
    else {
        $dc | ForEach-Object { Add-Detail "DC policy AuditNTLMInDomain = $($_.Value) in GPO $($_.Gpo)" }
        if (-not ($dc | Where-Object { [int]$_.Value -gt 0 })) { $problems += 'DC policy AuditNTLMInDomain is 0' }
    }
} else {
    Add-Detail 'Not joined to an AD domain, so the DC policy part does not apply.'
}
if ($problems.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($problems -join '; ')." }
Write-Verdict -Verdict 'PASS' -Summary 'NTLM use is audited here (in and out) and at the DCs.'
