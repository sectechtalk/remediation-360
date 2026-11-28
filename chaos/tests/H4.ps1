# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$g = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(sAMAccountName=provAgentgMSA*)' -Property 'samaccountname', 'msds-groupmsamembership')
if ($g.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'Cloud Sync is not used (no provAgentgMSA account).' }
$bad = @()
foreach ($a in $g) {
    $sd = New-Object -TypeName System.DirectoryServices.ActiveDirectorySecurity
    $sd.SetSecurityDescriptorBinaryForm([byte[]]$a.'msds-groupmsamembership')
    foreach ($rule in $sd.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        $o = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter "(objectSid=$sid)" -Property 'samaccountname', 'objectclass')
        $isComputer = $o.Count -gt 0 -and @($o[0].objectclass) -contains 'computer'
        Add-Detail "$($a.samaccountname): $(Resolve-SidName -Sid $sid)$(if (-not $isComputer) { ' (not a computer)' })"
        if (-not $isComputer) { $bad += (Resolve-SidName -Sid $sid) }
    }
}
if ($bad.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "the Cloud Sync gMSA can be used by more than agent servers: $($bad -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary 'only agent computers can use the Cloud Sync gMSA.'
