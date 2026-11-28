# uses: Reg, Ad, Sysvol
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$problems = @()
$aesOnly = { param($v) $n = [int64]$v -band 0x1F; (($n -band 0x7) -eq 0) -and (($n -band 0x18) -ne 0) }
$local = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'SupportedEncryptionTypes'
Add-Detail "This machine SupportedEncryptionTypes = $(if ($null -eq $local) { 'not set' } else { '0x{0:X}' -f [int64]$local })"
if ($null -eq $local -or -not (& $aesOnly $local)) { $problems += 'this machine does not limit Kerberos to AES' }
$dc = @(Find-DcGpoRegistryValue -Context $ctx -Pattern 'Kerberos\\Parameters\\SupportedEncryptionTypes')
if ($dc.Count -eq 0) { $problems += 'no DC policy limits Kerberos to AES'; Add-Detail 'DC policy SupportedEncryptionTypes: not set' }
foreach ($d in $dc) {
    Add-Detail "DC policy SupportedEncryptionTypes = 0x$('{0:X}' -f [int64]$d.Value) in GPO $($d.Gpo)"
    if (-not (& $aesOnly $d.Value)) { $problems += "GPO $($d.Gpo) allows more than AES" }
}
$noAes = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(&(samAccountType=805306368)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=krbtgt)))' -Property 'samaccountname', 'msds-supportedencryptiontypes' | Where-Object { $null -eq $_.'msds-supportedencryptiontypes' -or -not ([int]$_.'msds-supportedencryptiontypes' -band 0x18) } | ForEach-Object { [string]$_.samaccountname })
if ($noAes.Count -gt 0) { $problems += "$($noAes.Count) service account(s) without AES"; Add-Detail "Service accounts without AES: $((@($noAes) | Select-Object -First 25) -join ', ')" }
if ($problems.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($problems -join '; ')." }
Write-Verdict -Verdict 'PASS' -Summary 'DC policy and this machine allow AES only, and every service account has AES.'
